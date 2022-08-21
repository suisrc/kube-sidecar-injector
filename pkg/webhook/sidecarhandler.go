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

func createContainersPatches(newContainers []corev1.Container, existingContainers []corev1.Container, path string) []admission.PatchOperation {
	if len(existingContainers) == 0 {
		// pass merge patch if no existing containers
		return createArrayPatches(newContainers, existingContainers, path)
	}
	// merge existing and new containers
	var patches []admission.PatchOperation
	matchExistPod, _ := regexp.Compile(`^\[\d+\]$`)
	for index, item := range newContainers {
		if !matchExistPod.MatchString(item.Name) {
			first := index == 0 && len(existingContainers) == 0
			patches = append(patches, createArrayPatche(item, first, path))
			continue
		}
		idx, _ := strconv.Atoi(item.Name[1 : len(item.Name)-1]) // [0] -> current running container
		if idx < 0 || idx >= len(existingContainers) {
			continue // skip non-exist pod container, not found in existingContainers
		}
		// update existing pod container
		existContainer := existingContainers[idx]
		indexPath := fmt.Sprintf("%s/%d", path, idx)

		// update existing pod container
		patches = append(patches, createArrayPatches(item.EnvFrom, existContainer.EnvFrom, indexPath+"/envFrom")...)
		patches = append(patches, createArrayPatches(item.Env, existContainer.Env, indexPath+"/env")...)
		patches = append(patches, createArrayPatches(item.VolumeMounts, existContainer.VolumeMounts, indexPath+"/volumeMounts")...)
		patches = append(patches, createArrayPatches(item.VolumeDevices, existContainer.VolumeDevices, indexPath+"/volumeDevices")...)

		if item.LivenessProbe != nil && existContainer.LivenessProbe == nil {
			patches = append(patches, admission.PatchOperation{Op: "add", Path: indexPath + "/livenessProbe", Value: item.LivenessProbe})
		}
		if item.ReadinessProbe != nil && existContainer.ReadinessProbe == nil {
			patches = append(patches, admission.PatchOperation{Op: "add", Path: indexPath + "/readinessProbe", Value: item.ReadinessProbe})
		}
		if item.Lifecycle != nil && existContainer.Lifecycle == nil {
			patches = append(patches, admission.PatchOperation{Op: "add", Path: indexPath + "/lifecycle", Value: item.Lifecycle})
		}
		if item.SecurityContext != nil && existContainer.SecurityContext == nil {
			patches = append(patches, admission.PatchOperation{Op: "add", Path: indexPath + "/securityContext", Value: item.SecurityContext})
		}
	}
	return patches
}

func createArrayPatches[T any](newCollection []T, existingCollection []T, path string) []admission.PatchOperation {
	var patches []admission.PatchOperation
	for index, item := range newCollection {
		first := index == 0 && len(existingCollection) == 0
		patches = append(patches, createArrayPatche(item, first, path))
	}
	return patches
}

func createArrayPatche[T any](item T, first bool, path string) admission.PatchOperation {
	var value interface{}
	if !first {
		path = path + "/-"
		value = item
	} else {
		value = []T{item}
	}
	return admission.PatchOperation{
		Op:    "add",
		Path:  path,
		Value: value,
	}
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
				patches = append(patches, createContainersPatches(configmapSidecar.InitContainers, pod.Spec.InitContainers, "/spec/initContainers")...)
				patches = append(patches, createContainersPatches(configmapSidecar.Containers, pod.Spec.Containers, "/spec/containers")...)
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
