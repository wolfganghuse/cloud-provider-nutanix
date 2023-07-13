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
	"github.com/google/uuid"

	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cloudprovider "k8s.io/cloud-provider"
)

type loadBalancers struct {
	nutanixManager *nutanixManager
}

func newLoadBalancers(nutanixManager *nutanixManager) cloudprovider.LoadBalancer {
	return &loadBalancers{
		nutanixManager: nutanixManager,
	}
}

func (l *loadBalancers) GetLoadBalancer(ct context.Context, clusterName string, service *v1.Service) (status *v1.LoadBalancerStatus, exists bool, err error) {

	klog.Infof("GetLoadBalancer| clusterName: %s, service: %s, namespace: %s", clusterName, service.Name, service.Namespace)
	if service.Labels["implementation"] == "nutanix-ipam" {
		return &service.Status.LoadBalancer, true, nil
	}
	return nil, false, nil
}

// GetLoadBalancerName returns the name of the load balancer. Implementations must treat the
// *v1.Service parameter as read-only and not modify it.
func (l *loadBalancers) GetLoadBalancerName(ct context.Context, clusterName string, service *v1.Service) string {
	klog.Infof("GetLoadBalancerName| clusterName: %s, service: %s, namespace: %s", clusterName, service.Name, service.Namespace)
	return getDefaultLoadBalancerName(service)
}

func getDefaultLoadBalancerName(service *v1.Service) string {
	return cloudprovider.DefaultLoadBalancerName(service)
}

// It adds an entry "create" into the internal method call record.
func (l *loadBalancers) EnsureLoadBalancer(ct context.Context,
	clusterName string, service *v1.Service, nodes []*v1.Node) (
	*v1.LoadBalancerStatus, error,
) {
	klog.Info("EnsureLoadBalancer")
	klog.Infof("syncing service '%s' (%s)", service.Name, service.UID)
	
	// The loadBalancer address has already been populated
	if service.Spec.LoadBalancerIP != "" {
		return &service.Status.LoadBalancer, nil
	} 

	SubnetLabel:=service.Labels["nutanix-subnet"]
	if SubnetLabel=="" {
		klog.Infof("Label nutanix-subnet not set, ignoring SVC")
		return nil, fmt.Errorf("Label nutanix-subnet not set, ignoring SVC")
	}


	nc:=l.nutanixManager.nutanixClient.(*nutanixClient)
	SubnetUUID, err:=findSubnetByName(*nc,SubnetLabel)
	if err != nil {
		return nil, err
	}
	ClientContext := uuid.NewString()
	myIP, err:= ReserveIP(*nc,*SubnetUUID.ExtId,ClientContext)
	if err != nil {
		return nil, err
	}
	loadBalancerIP:=*myIP.Ipv4.Value

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		l.nutanixManager.nutanixClient.Get()
		recentService, getErr := l.nutanixManager.client.CoreV1().Services(service.Namespace).Get(ct, service.Name, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}

		klog.Infof("Updating service [%s], with load balancer IPAM address [%s]", service.Name, loadBalancerIP)

		if recentService.Labels == nil {
			// Just because ..
			recentService.Labels = make(map[string]string)
		}
		// Set Label for service lookups
		recentService.Labels["implementation"] = "nutanix-ipam"
		recentService.Labels["ipam-address"] = loadBalancerIP
		recentService.Labels["ip-uuid"] = ClientContext

		// Set IPAM address to Load Balancer Service
		recentService.Spec.LoadBalancerIP = loadBalancerIP

		// Update the actual service with the address and the labels
		_, updateErr := l.nutanixManager.client.CoreV1().Services(recentService.Namespace).Update(ct, recentService, metav1.UpdateOptions{})
		return updateErr
	})
	if retryErr != nil {
		return nil, fmt.Errorf("error updating Service Spec [%s] : %v", service.Name, retryErr)
	}

	return &service.Status.LoadBalancer, nil
}

func (l *loadBalancers) UpdateLoadBalancer(ct context.Context,
	clusterName string, service *v1.Service, nodes []*v1.Node,
) error {
	klog.Info("UpdateLoadBalancer")
	return nil
}

// EnsureLoadBalancerDeleted is a test-spy implementation of LoadBalancer.EnsureLoadBalancerDeleted.
// It adds an entry "delete" into the internal method call record.
func (l *loadBalancers) EnsureLoadBalancerDeleted(ct context.Context, clusterName string,
	service *v1.Service,
) error {
	nc:=l.nutanixManager.nutanixClient.(*nutanixClient)
	
	klog.Info("EnsureLoadBalancerDeleted")
	ClientContext:=service.Labels["ip-uuid"]
	klog.Info("Releasing IP with ClientContext: %s", ClientContext)




	SubnetLabel:=service.Labels["nutanix-subnet"]
	SubnetUUID, err:=findSubnetByName(*nc,SubnetLabel)
	if err != nil {
		return err
	}

	err = UnreserveIP(*nc,*SubnetUUID.ExtId,ClientContext)
	if err != nil {
		return err
	}
	return nil
}
