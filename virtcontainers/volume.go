//
// Copyright (c) 2017 HyperHQ Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package virtcontainers

import (
	"fmt"

	"github.com/hyperhq/runv/api"
	"github.com/hyperhq/runv/hypervisor"
)

type VolumeConfig struct {
	ID           string
	Source       string
	Format       string
	Fstype       string
	DockerVolume bool
	ReadOnly     bool
	Rbd          *RbdOptions
}

type RbdOptions struct {
	User     string
	Keyring  string
	Monitors []string
}

// Mount describes a container mount.
type Mount struct {
	MountPath string
	ReadOnly  bool
}

type VolumeReference struct {
	// ID matches PodVolume.ID
	ID     string
	Mounts []Mount
	// Details must be set when ID does not ref existing volumes in pod
	Details *VolumeConfig
}

type PodVolume struct {
	config *VolumeConfig
}

func newPodVolume(config *VolumeConfig) *PodVolume {
	return &PodVolume{config: config}
}

func newVolumes(pod *Pod, volConfigs []VolumeConfig) ([]*PodVolume, error) {
	var vols []*PodVolume
	existed := make(map[string]bool)
	for _, v := range volConfigs {
		if !existed[v.ID] {
			vols = append(vols, newPodVolume(&v))
			existed[v.ID] = true
		} else {
			return nil, fmt.Errorf("duplicated volume %s in config", v.ID)
		}
	}

	return vols, nil
}

func (v *PodVolume) toRunvDescription() *api.VolumeDescription {
	desc := &api.VolumeDescription{
		Name:         v.config.ID,
		Source:       v.config.Source,
		Format:       v.config.Format,
		Fstype:       v.config.Fstype,
		DockerVolume: v.config.DockerVolume,
		ReadOnly:     v.config.ReadOnly,
	}

	if v.config.Rbd != nil {
		desc.Options = &api.VolumeOption{
			User:     v.config.Rbd.User,
			Keyring:  v.config.Rbd.Keyring,
			Monitors: v.config.Rbd.Monitors,
		}
	}

	return desc
}

func (v *PodVolume) insert(vm *hypervisor.Vm) error {
	r := vm.AddVolume(v.toRunvDescription())
	if !r.IsSuccess() {
		return fmt.Errorf("failed to insert volume: %s", r.Message())
	}

	return nil
}

func (v *PodVolume) remove(vm *hypervisor.Vm) error {
	r := vm.RemoveVolume(v.config.ID)
	if !r.IsSuccess() {
		return fmt.Errorf("failed to remove volume: %s", r.Message())
	}

	return nil
}
