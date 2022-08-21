package webhook

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/suisrc/kube-sidecar-injector/pkg/admission"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Sidecar Kubernetes Sidecar Injector schema
type Sidecar struct {
	InitContainers   []corev1.Container            `yaml:"initContainers"`
	Containers       []corev1.Container            `yaml:"containers"`
	Volumes          []corev1.Volume               `yaml:"volumes"`
	ImagePullSecrets []corev1.LocalObjectReference `yaml:"imagePullSecrets"`
	Annotations      map[string]string             `yaml:"annotations"`
	Labels           map[string]string             `yaml:"labels"`
}

// SidecarInjectorPatcher Sidecar Injector patcher
type SidecarInjectorPatcher struct {
	K8sClient                kubernetes.Interface
	InjectPrefix             string
	InjectName               string
	SidecarDataKey           string
	AllowAnnotationOverrides bool
	AllowLabelOverrides      bool
}

func (patcher *SidecarInjectorPatcher) sideCarInjectionAnnotation() string {
	return patcher.InjectPrefix + "/" + patcher.InjectName
}

//==================================================================================================================================================================

func (patcher *SidecarInjectorPatcher) configmapSidecarData(ctx context.Context, configSidecarNamespace, configSidecarName string, pod corev1.Pod) (*Sidecar, error) {
	namespace := configSidecarNamespace // namespace of the configmap
	configKey := patcher.SidecarDataKey // key of the configmap
	configName := configSidecarName
	if idx := strings.IndexRune(configName, '/'); idx > 0 {
		namespace = configName[:idx]
		configName = configName[idx+1:]
	}
	if idx := strings.IndexRune(configName, '#'); idx > 0 {
		configKey = configName[idx+1:]
		configName = configName[:idx]
	}
	configMap, err := patcher.K8sClient.CoreV1().ConfigMaps(namespace).Get(ctx, configName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if sidecarStr, ok := configMap.Data[configKey]; !ok {
		return nil, fmt.Errorf("configmap %v does not contain key %v", configName, configKey)
	} else {
		sidecar := &Sidecar{}
		if err := yaml.Unmarshal([]byte(sidecarStr), sidecar); err != nil {
			return nil, fmt.Errorf("failed to parse configmap %v key %v: %v", configName, configKey, err)
		}
		matchExistPod, _ := regexp.Compile(`^\[\d+\]$`)
		for i := 0; i < len(sidecar.Containers); {
			if !matchExistPod.MatchString(sidecar.Containers[i].Name) {
				i++ // skip non-exist pod container
				continue
			}
			idx, _ := strconv.Atoi(sidecar.Containers[i].Name[1 : len(sidecar.Containers[i].Name)-1])
			if idx < 0 || idx >= len(pod.Spec.Containers) {
				// skip non-exist pod container
				sidecar.Containers = append(sidecar.Containers[:i], sidecar.Containers[i+1:]...)
			} else {
				sidecar.Containers[i].Name = pod.Spec.Containers[idx].Name
				i++ // replace container name
			}
		}
		return sidecar, nil
	}
}

func (patcher *SidecarInjectorPatcher) configmapSidecarNames(namespace string, pod corev1.Pod) []string {
	podName := pod.GetName()
	if podName == "" {
		podName = pod.GetGenerateName()
	}
	annotations := map[string]string{}
	if pod.GetAnnotations() != nil {
		annotations = pod.GetAnnotations()
	}
	if sidecars, ok := annotations[patcher.sideCarInjectionAnnotation()]; ok {
		parts := lo.Map(strings.Split(sidecars, ","), func(part string, _ int) string { // Map[string, string]
			return strings.TrimSpace(part)
		})

		if len(parts) > 0 {
			log.Infof("sideCar injection for %v/%v: sidecars: %v", namespace, podName, sidecars)
			return parts
		}
	}
	log.Infof("Skipping mutation for [%v]. No action required", podName)
	return nil
}

//==================================================================================================================================================================

func (patcher *SidecarInjectorPatcher) fixSidecarByPodAnnotations(sidecar *Sidecar, annotations map[string]string) {
	if (annotations == nil) || (len(annotations) == 0) {
		return
	}
	envPrefixKey := patcher.InjectPrefix + "/env."
	for envName, envValue := range annotations {
		if strings.HasPrefix(envName, envPrefixKey) {
			envName = envName[len(envPrefixKey):]
			for idx := range sidecar.InitContainers {
				patcher.fixSidecarContainerEnvValue(&sidecar.Containers[idx], envName, envValue)
			}
			for idx := range sidecar.Containers {
				patcher.fixSidecarContainerEnvValue(&sidecar.Containers[idx], envName, envValue)
			}
		}
	}
}

func (patcher *SidecarInjectorPatcher) fixSidecarContainerEnvValue(container *corev1.Container, envName, envValue string) {
	edx := -1
	for jdx := range container.Env {
		if container.Env[jdx].Name == envName {
			edx = jdx
			break
		}
	}
	if edx >= 0 {
		// update existing env value
		container.Env[edx].Value = envValue
	} else {
		// add new env value
		container.Env = append(container.Env, corev1.EnvVar{Name: envName, Value: envValue})
	}
}

//==================================================================================================================================================================

func createArrayPatches[T any](newCollection []T, existingCollection []T, path string) []admission.PatchOperation {
	var patches []admission.PatchOperation
	for index, item := range newCollection {
		indexPath := path
		var value interface{}
		first := index == 0 && len(existingCollection) == 0
		if !first {
			indexPath = indexPath + "/-"
			value = item
		} else {
			value = []T{item}
		}
		patches = append(patches, admission.PatchOperation{
			Op:    "add",
			Path:  indexPath,
			Value: value,
		})
	}
	return patches
}

func createObjectPatches(newMap map[string]string, existingMap map[string]string, path string, override bool) []admission.PatchOperation {
	var patches []admission.PatchOperation
	if existingMap == nil {
		patches = append(patches, admission.PatchOperation{
			Op:    "add",
			Path:  path,
			Value: newMap,
		})
	} else {
		for key, value := range newMap {
			if _, ok := existingMap[key]; !ok || (ok && override) {
				key = escapeJSONPath(key)
				op := "add"
				if ok {
					op = "replace"
				}
				patches = append(patches, admission.PatchOperation{
					Op:    op,
					Path:  path + "/" + key,
					Value: value,
				})
			}
		}
	}
	return patches
}

// Escape keys that may contain `/`s or `~`s to have a valid patch
// Order matters here, otherwise `/` --> ~01, instead of ~1
func escapeJSONPath(k string) string {
	k = strings.ReplaceAll(k, "~", "~0")
	return strings.ReplaceAll(k, "/", "~1")
}

//==================================================================================================================================================================

// PatchPodCreate Handle Pod Create Patch
func (patcher *SidecarInjectorPatcher) PatchPodCreate(ctx context.Context, namespace string, pod corev1.Pod) ([]admission.PatchOperation, error) {
	podName := pod.GetName()
	if podName == "" {
		podName = pod.GetGenerateName()
	}
	var patches []admission.PatchOperation
	if configmapSidecarNames := patcher.configmapSidecarNames(namespace, pod); configmapSidecarNames != nil {
		for _, configmapSidecarName := range configmapSidecarNames {
			configmapSidecar, err := patcher.configmapSidecarData(ctx, namespace, configmapSidecarName, pod)
			if k8serrors.IsNotFound(err) {
				log.Warnf("sidecar configmap %s -> %s was not found for %s/%s pod", namespace, configmapSidecarName, namespace, podName)
			} else if err != nil {
				log.Errorf("error fetching sidecar configmap %s -> %s for %s/%s pod - %v", namespace, configmapSidecarName, namespace, podName, err)
			} else if configmapSidecar != nil {
				patcher.fixSidecarByPodAnnotations(configmapSidecar, pod.GetAnnotations()) // fix sidecar by pod annotations
				patches = append(patches, createArrayPatches(configmapSidecar.InitContainers, pod.Spec.InitContainers, "/spec/initContainers")...)
				patches = append(patches, createArrayPatches(configmapSidecar.Containers, pod.Spec.Containers, "/spec/containers")...)
				patches = append(patches, createArrayPatches(configmapSidecar.Volumes, pod.Spec.Volumes, "/spec/volumes")...)
				patches = append(patches, createArrayPatches(configmapSidecar.ImagePullSecrets, pod.Spec.ImagePullSecrets, "/spec/imagePullSecrets")...)
				patches = append(patches, createObjectPatches(configmapSidecar.Annotations, pod.Annotations, "/metadata/annotations", patcher.AllowAnnotationOverrides)...)
				patches = append(patches, createObjectPatches(configmapSidecar.Labels, pod.Labels, "/metadata/labels", patcher.AllowLabelOverrides)...)
			}
		}
	}
	log.Debugf("sidecar patches being applied for %v/%v: patches: %v", namespace, podName, patches)
	return patches, nil
}

/*PatchPodUpdate not supported, only support create */
func (patcher *SidecarInjectorPatcher) PatchPodUpdate(_ context.Context, _ string, _ corev1.Pod, _ corev1.Pod) ([]admission.PatchOperation, error) {
	return nil, nil
}

/*PatchPodDelete not supported, only support create */
func (patcher *SidecarInjectorPatcher) PatchPodDelete(_ context.Context, _ string, _ corev1.Pod) ([]admission.PatchOperation, error) {
	return nil, nil
}
