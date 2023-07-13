/*
Copyright 2022 Nutanix, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"context"
	"fmt"
	"encoding/json"
	
	"os"

	prismgoclient "github.com/nutanix-cloud-native/prism-go-client"
	"github.com/nutanix-cloud-native/prism-go-client/environment"
	credentialTypes "github.com/nutanix-cloud-native/prism-go-client/environment/credentials"
	kubernetesEnv "github.com/nutanix-cloud-native/prism-go-client/environment/providers/kubernetes"
	envTypes "github.com/nutanix-cloud-native/prism-go-client/environment/types"
	prismClientV3 "github.com/nutanix-cloud-native/prism-go-client/v3"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/nutanix-cloud-native/cloud-provider-nutanix/internal/constants"
	"github.com/nutanix-cloud-native/cloud-provider-nutanix/pkg/provider/config"
	"github.com/nutanix-cloud-native/cloud-provider-nutanix/pkg/provider/interfaces"

	b64 "encoding/base64"

	networkingapi "github.com/nutanix-core/ntnx-api-go-sdk-internal/networking_go_sdk/v16/api"
	networkingconfig "github.com/nutanix-core/ntnx-api-go-sdk-internal/networking_go_sdk/v16/models/networking/v4/config"
	prism "github.com/nutanix-core/ntnx-api-go-sdk-internal/networking_go_sdk/v16/models/prism/v4/config"
	tasksapi "github.com/nutanix-core/ntnx-api-go-sdk-internal/tasks_go_sdk/v16/api"
	tasksprism "github.com/nutanix-core/ntnx-api-go-sdk-internal/tasks_go_sdk/v16/models/prism/v4/config"
	//"k8s.io/klog/v2"

	common "github.com/nutanix-core/ntnx-api-go-sdk-internal/networking_go_sdk/v16/models/common/v1/config"

)

const errEnvironmentNotReady = "environment not initialized or ready yet"

type v4config struct {
	SubnetReserveUnreserveIPAPIClient *networkingapi.SubnetReserveUnreserveIpApi
	TasksAPIClient *tasksapi.TaskApi
	SubnetIPAPIClient *networkingapi.SubnetApi
}
type nutanixClient struct {
	env             envTypes.Environment
	config          config.Config
	secretInformer  coreinformers.SecretInformer
	sharedInformers informers.SharedInformerFactory
  configMapInformer coreinformers.ConfigMapInformer
	v4config		v4config
}

type reservedIP struct {
    IP []string      `json:"reserved_ips"`
}

func (n *nutanixClient) Get() (interfaces.Prism, error) {
	if err := n.setupEnvironment(); err != nil {
		return nil, fmt.Errorf("%s: %v", errEnvironmentNotReady, err)
	}
	env := *n.env
	me, err := env.GetManagementEndpoint(envTypes.Topology{})
	if err != nil {
		return nil, err
	}
	creds := &prismgoclient.Credentials{
		URL:      me.Address.Host, // Not really an URL
		Endpoint: me.Address.Host,
		Insecure: me.Insecure,
		Username: me.ApiCredentials.Username,
		Password: me.ApiCredentials.Password,
	}

	clientOpts := make([]prismClientV3.ClientOption, 0)
	if me.AdditionalTrustBundle != "" {
		clientOpts = append(clientOpts, prismClientV3.WithPEMEncodedCertBundle([]byte(me.AdditionalTrustBundle)))
	}

	nutanixClient, err := prismClientV3.NewV3Client(*creds, clientOpts...)
	if err != nil {
		return nil, err
	}

	_, err = nutanixClient.V3.GetCurrentLoggedInUser(context.Background())
	if err != nil {
		return nil, err
	}
	n.v4config.SubnetReserveUnreserveIPAPIClient = networkingapi.NewSubnetReserveUnreserveIpApi()
	n.v4config.SubnetReserveUnreserveIPAPIClient.ApiClient.BasePath = "https://" + me.Address.Host
	n.v4config.SubnetReserveUnreserveIPAPIClient.ApiClient.SetVerifySSL(false)
	n.v4config.SubnetReserveUnreserveIPAPIClient.ApiClient.Debug = false
	n.v4config.SubnetReserveUnreserveIPAPIClient.ApiClient.DefaultHeaders = map[string]string{
		"Authorization": fmt.Sprintf("Basic %s",
			b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", me.ApiCredentials.Username, me.ApiCredentials.Password)))),
	}


	n.v4config.TasksAPIClient = tasksapi.NewTaskApi()
	n.v4config.TasksAPIClient.ApiClient.BasePath = "https://" + me.Address.Host
	n.v4config.TasksAPIClient.ApiClient.SetVerifySSL(false)
	n.v4config.TasksAPIClient.ApiClient.Debug = false
	n.v4config.TasksAPIClient.ApiClient.DefaultHeaders = map[string]string{
		"Authorization": fmt.Sprintf("Basic %s",
			b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", me.ApiCredentials.Username, me.ApiCredentials.Password)))),
	}
 
	n.v4config.SubnetIPAPIClient = networkingapi.NewSubnetApi()
	n.v4config.SubnetIPAPIClient.ApiClient.BasePath = "https://" + me.Address.Host
	n.v4config.SubnetIPAPIClient.ApiClient.SetVerifySSL(false)
	n.v4config.SubnetIPAPIClient.ApiClient.Debug = false
	n.v4config.SubnetIPAPIClient.ApiClient.DefaultHeaders = map[string]string{
		"Authorization": fmt.Sprintf("Basic %s",
			b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", me.ApiCredentials.Username, me.ApiCredentials.Password)))),
	}

	return nutanixClient.V3, nil
}

func (n *nutanixClient) setupEnvironment() error {
	if n.env != nil {
		return nil
	}
	ccmNamespace, err := n.getCCMNamespace()
	if err != nil {
		return err
	}
	pc := n.config.PrismCentral
	if pc.CredentialRef != nil {
		if pc.CredentialRef.Namespace == "" {
			pc.CredentialRef.Namespace = ccmNamespace
		}
	}
	additionalTrustBundleRef := pc.AdditionalTrustBundle
	if additionalTrustBundleRef != nil &&
		additionalTrustBundleRef.Kind == credentialTypes.NutanixTrustBundleKindConfigMap &&
		additionalTrustBundleRef.Namespace == "" {
		additionalTrustBundleRef.Namespace = ccmNamespace
	}

	env := environment.NewEnvironment(kubernetesEnv.NewProvider(pc,
		n.secretInformer, n.configMapInformer))
	n.env = &env
	return nil
}

func (n *nutanixClient) SetInformers(sharedInformers informers.SharedInformerFactory) {
	n.sharedInformers = sharedInformers
	n.secretInformer = n.sharedInformers.Core().V1().Secrets()
	n.configMapInformer = n.sharedInformers.Core().V1().ConfigMaps()
	n.syncCache(n.secretInformer.Informer())
	n.syncCache(n.configMapInformer.Informer())
}

func (n *nutanixClient) syncCache(informer cache.SharedInformer) {
	hasSynced := informer.HasSynced
	if !hasSynced() {
		stopCh := context.Background().Done()
		go informer.Run(stopCh)
		if ok := cache.WaitForCacheSync(stopCh, hasSynced); !ok {
			klog.Fatal("failed to wait for caches to sync")
		}
	}
}

func (n *nutanixClient) getCCMNamespace() (string, error) {
	ns := os.Getenv(constants.CCMNamespaceKey)
	if ns == "" {
		return "", fmt.Errorf("failed to retrieve CCM namespace. Make sure %s env variable is set", constants.CCMNamespaceKey)
	}
	return ns, nil
}


// ReserveIP returns single IP, needs Subnet UUID and ClientContext
func ReserveIP(n nutanixClient, SubnetUUID string, ClientContext string) (*common.IPAddress, error) {
	var ClientCount int64 = 1
	ipReserveInput:=networkingconfig.NewIpReserveInput()
	ipReserveInput.ClientContext = &ClientContext
	ipReserveInput.Count = &ClientCount
	ipReserveInput.ReserveType = networkingconfig.RESERVETYPE_IP_ADDRESS_COUNT.Ref()
	
	response, err := n.v4config.SubnetReserveUnreserveIPAPIClient.ReserveIps(ipReserveInput, SubnetUUID)   
	if err != nil {
		klog.Errorf("error while SubnetReserveUnreserveIpApiClient.ReserveIps | ipReserveInput: %s, Subnet_UUID: %s| error: %s", ipReserveInput, SubnetUUID,err.Error())
		return nil , err
	} 
	data := response.GetData().(prism.TaskReference)
	responsetask, err := n.v4config.TasksAPIClient.TaskGet(*data.ExtId)
	if err != nil {
		klog.Errorf("error while TasksApiClient.TaskGet | error: %s", err.Error())
		return nil , err
	}

	ReservedIPv4:=common.NewIPv4Address()
	ipResponse:=reservedIP{}
	output := responsetask.GetData().(tasksprism.Task)
	for _ ,details:= range output.CompletionDetails {
		s:=details.Value.GetValue().(string)
		json.Unmarshal([]byte(s), &ipResponse)
		ReservedIPv4.Value=&ipResponse.IP[0]
	}
	ReservedIP:=common.NewIPAddress()
	ReservedIP.Ipv4=ReservedIPv4
	return ReservedIP,nil
}

// UnreserveIP returns Err of nil if release was successful, needs Subnet UUID and ClientContext
func UnreserveIP(n nutanixClient, SubnetUUID string, ClientContext string) (error) {
	IPUnreserveInput:=networkingconfig.NewIpUnreserveInput()
	IPUnreserveInput.UnreserveType= networkingconfig.UNRESERVETYPE_CONTEXT.Ref()
	IPUnreserveInput.ClientContext=&ClientContext
	response, err := n.v4config.SubnetReserveUnreserveIPAPIClient.UnreserveIps(IPUnreserveInput,SubnetUUID)
	if err != nil {
		return err
	}
	//ToDo: return failure if clientcontext does not match
	data := response.GetData().(prism.TaskReference)
	_, err = n.v4config.TasksAPIClient.TaskGet(*data.ExtId)
	if err != nil {
		return err
	}
	return nil
}

//findSubnetByName returns Subnet UUID, needs name
func findSubnetByName(n nutanixClient, name string) (*networkingconfig.Subnet, error) {
	page := 0
	limit := 20
	filter := fmt.Sprintf("name eq '%[1]v'", name)
	response, err := n.v4config.SubnetIPAPIClient.ListSubnets(
		&page, &limit, &filter, nil, nil)
	if err != nil {
		return nil , err
	}

	if *response.Metadata.TotalAvailableResults > 1 {
		return nil, fmt.Errorf("your query returned more than one result. Please use subnet_uuid argument or use additional filters instead")
	}

	if *response.Metadata.TotalAvailableResults == 0{
		return nil, fmt.Errorf("subnet with the given name, not found")
	}

	if response.GetData() == nil {
		return nil, fmt.Errorf("subnet query call failed")
	}
	found:=networkingconfig.NewSubnet()
	for _, data := range response.GetData().([]networkingconfig.Subnet) {
		found=&data
	}
	return found, nil
}
