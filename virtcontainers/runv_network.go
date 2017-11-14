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
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/hyperhq/runv/api"
	_ "github.com/hyperhq/runv/cli/nsenter"
	"github.com/hyperhq/runv/hypervisor"
	"github.com/vishvananda/netlink"
)

type NetlinkUpdateType string

const (
	UpdateTypeLink  NetlinkUpdateType = "link"
	UpdateTypeAddr  NetlinkUpdateType = "addr"
	UpdateTypeRoute NetlinkUpdateType = "route"
	fakeBridge      string            = "runv0"
)

// NetlinkUpdate tracks the change of network namespace.
type NetlinkUpdate struct {
	// AddrUpdate is used to pass information back from AddrSubscribe()
	Addr netlink.AddrUpdate
	// RouteUpdate is used to pass information back from RouteSubscribe()
	Route netlink.RouteUpdate
	// Veth is used to pass information back from LinkSubscribe().
	// We only support veth link at present.
	Veth *netlink.Veth

	// UpdateType indicates which part of the netlink information has been changed.
	UpdateType NetlinkUpdateType
}

type InterfaceInfo struct {
	Index     int
	PeerIndex int
	Ip        string
	Mac       string
	Name      string
	Mtu       uint64
}

type nsListener struct {
	enc *gob.Encoder
	dec *gob.Decoder
	cmd *exec.Cmd
}

type tcMirredPair struct {
	NsIfIndex   int
	HostIfIndex int
}

func createFakeBridge() {
	// add an useless bridge to satisfy hypervisor, most of them need to join bridge.
	la := netlink.NewLinkAttrs()
	la.Name = fakeBridge
	bridge := &netlink.Bridge{LinkAttrs: la}
	if err := netlink.LinkAdd(bridge); err != nil && !os.IsExist(err) {
	}
}

func initSandboxNetwork(vm *hypervisor.Vm, enc *gob.Encoder, dec *gob.Decoder, pid int) error {
	/* send collect netns request to nsListener */
	if err := enc.Encode("init"); err != nil {
		return err
	}

	infos := []InterfaceInfo{}
	/* read nic information of ns from pipe */
	err := dec.Decode(&infos)
	if err != nil {
		return err
	}

	routes := []netlink.Route{}
	err = dec.Decode(&routes)
	if err != nil {
		return err
	}

	var gw_route *netlink.Route
	for idx, route := range routes {
		if route.Dst == nil {
			gw_route = &routes[idx]
		}
	}

	createFakeBridge()

	mirredPairs := []tcMirredPair{}
	for _, info := range infos {
		nicId := strconv.Itoa(info.Index)

		conf := &api.InterfaceDescription{
			Id:     nicId, //ip as an id
			Lo:     false,
			Bridge: fakeBridge,
			Ip:     info.Ip,
			Name:   info.Name,
			Mac:    info.Mac,
			Mtu:    info.Mtu,
		}

		if gw_route != nil && gw_route.LinkIndex == info.Index {
			conf.Gw = gw_route.Gw.String()
		}

		// TODO(hukeping): the name here is always eth1, 2, 3, 4, 5, etc.,
		// which would not be the proper way to name device name, instead it
		// should be the same as what we specified in the network namespace.
		//err = hp.vm.AddNic(info.Index, fmt.Sprintf("eth%d", idx), conf)
		if err = vm.AddNic(conf); err != nil {
			return err
		}

		// move device into container-shim netns
		hostLink, err := netlink.LinkByName(conf.TapName)
		if err != nil {
			return err
		}
		if err = netlink.LinkSetNsPid(hostLink, pid); err != nil {
			return err
		}
		mirredPairs = append(mirredPairs, tcMirredPair{info.Index, hostLink.Attrs().Index})
	}

	if err = enc.Encode(mirredPairs); err != nil {
		return err
	}

	if err = vm.AddRoute(); err != nil {
		return err
	}

	// TODO: does nsListener need to be long living?
	//go nsListenerStrap(vm, enc *gob.Encoder, dec *gob.Decoder)

	return nil
}

func nsListenerStrap(vm *hypervisor.Vm, enc *gob.Encoder, dec *gob.Decoder) {
	// Keep watching container network setting
	// and then update vm/hyperstart
	for {
		update := NetlinkUpdate{}
		err := dec.Decode(&update)
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		switch update.UpdateType {
		case UpdateTypeLink:
			link := update.Veth
			if link.Attrs().ParentIndex == 0 {
				err = vm.DeleteNic(strconv.Itoa(link.Attrs().Index))
				if err != nil {
					continue
				}

			} else {
			}

		case UpdateTypeAddr:

			link := update.Veth

			// If there is a delete operation upon an link, it will also trigger
			// the address change event which the link will be NIL since it has
			// already been deleted before the address change event be triggered.
			if link == nil {
				continue
			}

			// This is just a sanity check.
			//
			// The link should be the one which the address on it has been changed.
			if link.Attrs().Index != update.Addr.LinkIndex {
				continue
			}

			inf := &api.InterfaceDescription{
				Id:     strconv.Itoa(link.Attrs().Index),
				Lo:     false,
				Bridge: fakeBridge,
				Ip:     update.Addr.LinkAddress.String(),
			}

			err = vm.AddNic(inf)
			if err != nil {
				continue
			}

		case UpdateTypeRoute:

		}
	}
}

func newPipe() (parent, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), "parent"), os.NewFile(uintptr(fds[0]), "child"), nil
}

func startNsListener(container string, pid int, vm *hypervisor.Vm) (err error) {
	var parentPipe, childPipe *os.File

	parentPipe, childPipe, err = newPipe()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			parentPipe.Close()
			childPipe.Close()
		}
	}()

	env := append(os.Environ(), fmt.Sprintf("_RUNVNETNSPID=%d", pid))
	env = append(env, fmt.Sprintf("_RUNVCONTAINERID=%s", container))
	cmd := exec.Cmd{
		Path:       "runv",
		Args:       []string{"runv", "network-nslisten"},
		Env:        env,
		ExtraFiles: []*os.File{childPipe},
		Dir:        shareDirPath(vm),
	}
	if err = cmd.Start(); err != nil {
		return err
	}

	childPipe.Close()

	enc := gob.NewEncoder(parentPipe)
	dec := gob.NewDecoder(parentPipe)

	defer func() {
		if err != nil {
			cmd.Process.Kill()
		}
		cmd.Wait()
	}()

	/* Make sure nsListener create new netns */
	var ready string
	if err = dec.Decode(&ready); err != nil {
		return err
	}

	if ready != "init" {
		err = fmt.Errorf("get incorrect init message from network-nslisten: %s", ready)
		return err
	}

	initSandboxNetwork(vm, enc, dec, cmd.Process.Pid)
	return nil
}
