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
	"strings"
	"strconv"
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

//	b64 "encoding/base64"

// adding public v4api
	apiv4 "github.com/nutanix/ntnx-api-golang-clients/networking-go-client/v4/api"
	networkingclientv4 "github.com/nutanix/ntnx-api-golang-clients/networking-go-client/v4/client"
	prismclientv4 "github.com/nutanix/ntnx-api-golang-clients/prism-go-client/v4/client"
	
	commonv4 "github.com/nutanix/ntnx-api-golang-clients/networking-go-client/v4/models/common/v1/config"
	networkingconfigv4 "github.com/nutanix/ntnx-api-golang-clients/networking-go-client/v4/models/networking/v4/config"
	prismv4 "github.com/nutanix/ntnx-api-golang-clients/networking-go-client/v4/models/prism/v4/config"
	prismapiv4 "github.com/nutanix/ntnx-api-golang-clients/prism-go-client/v4/api"
	prismconfigv4 "github.com/nutanix/ntnx-api-golang-clients/prism-go-client/v4/models/prism/v4/config"
)

const errEnvironmentNotReady = "environment not initialized or ready yet"

type v4config struct {
	SubnetReserveUnreserveIPAPIClient *apiv4.SubnetReserveUnreserveIpApi
	TasksAPIClient prismapiv4.TaskApi
	SubnetIPAPIClient *apiv4.SubnetApi
}

type nutanixClient struct {
	env             *envTypes.Environment
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
func ReserveIP(n nutanixClient, SubnetUUID string, ClientContext string) (*commonv4.IPAddress, error) {
	var ClientCount int64 = 1
	ReservedIP:=commonv4.NewIPAddress()
	
	ipReserveInput:=*networkingconfigv4.NewIpReserveInput()
	ipReserveInput.ClientContext = &ClientContext
	ipReserveInput.Count = &ClientCount
	ipReserveInput.ReserveType = networkingconfigv4.RESERVETYPE_IP_ADDRESS_COUNT.Ref()

	response, err := n.v4config.SubnetReserveUnreserveIPAPIClient.ReserveIps(&ipReserveInput, &SubnetUUID)   
	if err != nil {
		klog.Errorf("error while SubnetReserveUnreserveIpApiClient.ReserveIps | ipReserveInput: %s, Subnet_UUID: %s| error: %s", ipReserveInput, SubnetUUID,err.Error())
		return nil , err
	} 

	data := response.GetData().(prismv4.TaskReference)
	responsetask, err:= n.v4config.TasksAPIClient.TaskGet(data.ExtId)
	if err != nil {
		klog.Errorf("error while TasksApiClient.TaskGet | error: %s", err.Error())
		return nil , err
	}

	status, err := responsetask.GetData().(prismconfigv4.Task).Status.MarshalJSON()
	if string(status) == "\"FAILED\"" {
		return nil, fmt.Errorf(*responsetask.Data.GetValue().(prismconfigv4.Task).LegacyErrorMessage)
	}

	ReservedIPv4:=commonv4.NewIPv4Address()
	ipResponse:=reservedIP{}
	output := responsetask.GetData().(prismconfigv4.Task)
	
	for _ ,details:= range output.CompletionDetails {
		s:=details.Value.GetValue().(string)
		json.Unmarshal([]byte(s), &ipResponse)
		ReservedIPv4.Value=&ipResponse.IP[0]
	}
	ReservedIP.Ipv4=ReservedIPv4

	return ReservedIP,nil
}

// UnreserveIP returns Err of nil if release was successful, needs Subnet UUID and ClientContext
func UnreserveIP(n nutanixClient, SubnetUUID string, ClientContext string) (error) {
	IPUnreserveInput:=networkingconfigv4.NewIpUnreserveInput()

	IPUnreserveInput.UnreserveType= networkingconfigv4.UNRESERVETYPE_CONTEXT.Ref()
	IPUnreserveInput.ClientContext=&ClientContext

	response, err := n.v4config.SubnetReserveUnreserveIPAPIClient.UnreserveIps(IPUnreserveInput,&SubnetUUID)
	if err != nil {
		return err
	}
	data := response.GetData().(prismv4.TaskReference)
	resp, err := n.v4config.TasksAPIClient.TaskGet(data.ExtId)
	status, err := resp.GetData().(prismconfigv4.Task).Status.MarshalJSON()
	if string(status) == "\"FAILED\"" {
		return fmt.Errorf(*resp.Data.GetValue().(prismconfigv4.Task).LegacyErrorMessage)
	}

	if err != nil {
		return err
	}
	return nil
}


func connectv4(n nutanixClient, name string) (*nutanixClient, error) {
	klog.Infof("connect function: %s", name)
	if err := n.setupEnvironment(); err != nil {
		return nil, fmt.Errorf("%s: %v", errEnvironmentNotReady, err)
	}
	env := *n.env
	me, err := env.GetManagementEndpoint(envTypes.Topology{})
	if err != nil {
		return nil, err
	}
	klog.Infof("me: %s", me)
	klog.Infof("me.Address.Host: %s", me.Address.Host)
	urlparts := strings.Split(me.Address.Host, ":")

	klog.Info("Connecting V4...3")
	Port, err:= strconv.Atoi(urlparts[1])
	if err != nil {
		return nil, err
	} 
	Host:= urlparts[0]
	klog.Infof("Host: %s", Host)
	APIClientInstance := networkingclientv4.NewApiClient()
	APIClientInstance.Host = Host // IPv4/IPv6 address or FQDN of the cluster
	
	APIClientInstance.Port = Port // Port to which to connect to
	APIClientInstance.Username = me.ApiCredentials.Username // UserName to connect to the cluster
	APIClientInstance.Password = me.ApiCredentials.Password // Password to connect to the cluster
	
	//if me.Debug == "true" {
	APIClientInstance.Debug = true
	//}

	//if c.Insecure=="true" {
	APIClientInstance.SetVerifySSL(false)
	//} else {
	//	APIClientInstance.SetVerifySSL(true)
	//}

	PrismAPIClientInstance := prismclientv4.NewApiClient()
	PrismAPIClientInstance.Host = Host // IPv4/IPv6 address or FQDN of the cluster
	PrismAPIClientInstance.Port = Port // Port to which to connect to
	PrismAPIClientInstance.Username = me.ApiCredentials.Username // UserName to connect to the cluster
	PrismAPIClientInstance.Password = me.ApiCredentials.Password // Password to connect to the cluster

	//if c.Debug == "true" {
	PrismAPIClientInstance.Debug = true
	//}

	//if c.Insecure=="true" {
	PrismAPIClientInstance.SetVerifySSL(false)
	//} else {
	//	PrismAPIClientInstance.SetVerifySSL(true)
	//}

	n.v4config.SubnetReserveUnreserveIPAPIClient = apiv4.NewSubnetReserveUnreserveIpApi(APIClientInstance)
	n.v4config.SubnetIPAPIClient = apiv4.NewSubnetApi(APIClientInstance)
	n.v4config.TasksAPIClient = *prismapiv4.NewTaskApi(PrismAPIClientInstance)

	return &n, nil
}

//findSubnetByName returns Subnet UUID, needs name
func findSubnetByName(n nutanixClient, name string) (*networkingconfigv4.Subnet, error) {
	page := 0
	limit := 20
	filter := fmt.Sprintf("name eq '%[1]v'", name)
	klog.Infof("debug: %s",n.v4config.SubnetIPAPIClient)
	response, err := n.v4config.SubnetIPAPIClient.ListSubnets(
		&page, &limit, &filter, nil)
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
	found:=networkingconfigv4.NewSubnet()
	for _, data := range response.GetData().([]networkingconfigv4.Subnet) {
		found=&data
	}
	return found, nil
}
