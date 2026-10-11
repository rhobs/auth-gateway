//go:build e2e

package framework

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDeploymentRolloutCompleteWaitsForOldReplicasToExit(t *testing.T) {
	desired := int32(1)
	deployment := &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{Replicas: &desired},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration:  2,
			Replicas:            2,
			UpdatedReplicas:     1,
			AvailableReplicas:   2,
			UnavailableReplicas: 0,
		},
	}
	if deploymentRolloutComplete(deployment) {
		t.Fatal("rollout completed while an old replica was still present")
	}

	deployment.Status.Replicas = 1
	deployment.Status.AvailableReplicas = 1
	if !deploymentRolloutComplete(deployment) {
		t.Fatal("rollout was incomplete after only the updated replica remained available")
	}
}

func TestDeploymentRolloutCompleteRequiresObservedGeneration(t *testing.T) {
	desired := int32(1)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Generation: 2},
		Spec:       appsv1.DeploymentSpec{Replicas: &desired},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration:  1,
			Replicas:            1,
			UpdatedReplicas:     1,
			AvailableReplicas:   1,
			UnavailableReplicas: 0,
		},
	}
	if deploymentRolloutComplete(deployment) {
		t.Fatal("rollout completed before the new generation was observed")
	}
	deployment.Status.ObservedGeneration = 2
	if !deploymentRolloutComplete(deployment) {
		t.Fatal("rollout was incomplete after all desired replicas were available")
	}
}
