package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/pkg/errors"
	"gopkg.in/dsheets/docker.v999/volume/mountpoint"
	mountpointAPI "gopkg.in/dsheets/go-plugins-helpers.v999/mountpoint"
)

const (
	socketPath        = "/run/docker/plugins/transbind.sock"
	hostRoot          = "/host"
	pluginContentType = "application/vnd.docker.plugins.v1+json"
)

type Config struct {
	Root   string
	Socket string
}

func main() {
	debug := os.Getenv("DEBUG")

	if ok, _ := strconv.ParseBool(debug); ok {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if len(os.Args) < 3 {
		logrus.Fatalf("%s requires at least 2 arguments (root and socket)",
			os.Args[0])
	}

	config := Config{os.Args[1], os.Args[2]}

	p := newTransbindPlugin(config)

	h := mountpointAPI.NewHandler(p)
	logrus.Infof("listening on %s", socketPath)
	logrus.Error(h.ServeUnix(socketPath, 0))
}

type transbindPlugin struct {
	mu         sync.Mutex
	config     Config
	httpClient *http.Client
}

func newTransbindPlugin(config Config) transbindPlugin {
	root := hostRoot + config.Root
	if err := checkRoot(hostRoot + config.Root); err != nil {
		logrus.Fatalf("failure to create transbind plugin: root check of %s failed: %s", root, err)
		return transbindPlugin{}
	}

	httpClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return dialSock(config.Socket)
			},
		},
	}
	return transbindPlugin{
		config:     config,
		httpClient: httpClient,
	}
}

func (p transbindPlugin) Attach(req mountpoint.AttachRequest) mountpoint.AttachResponse {
	transBinds := p.transBinds(req)
	req.Mounts = filterNils(transBinds)

	if len(req.Mounts) == 0 {
		return mountpoint.AttachResponse{Success: true}
	}

	resp, err := post(p.httpClient, "http://server/TransbindPlugin.MountPointAttach", req)
	if err != nil {
		return mountpoint.AttachResponse{
			Success: false,
			Err:     fmt.Sprintf("Error posting attach to transbind server: %s", err),
		}
	}

	var attachResponse mountpoint.AttachResponse

	if err = json.Unmarshal(resp, &attachResponse); err != nil {
		return mountpoint.AttachResponse{
			Success: false,
			Err:     fmt.Sprintf("Error parsing attach response from transbind server: %s", err),
		}
	}

	if attachResponse.Success {
		attachments := attachResponse.Attachments
		attachIdx := 0
		attachResponse.Attachments = []mountpoint.Attachment{}
		for _, transBind := range transBinds {
			var attachment mountpoint.Attachment
			if transBind != nil {
				attachment = attachments[attachIdx]
				attachIdx++
			}
			attachResponse.Attachments = append(attachResponse.Attachments, attachment)
		}
	}

	return attachResponse
}

func (p transbindPlugin) transBinds(req mountpoint.AttachRequest) []*mountpoint.MountPoint {
	p.mu.Lock()
	defer p.mu.Unlock()
	var transBinds []*mountpoint.MountPoint

	for _, m := range req.Mounts {
		if m.Volume.Driver == "local" {
			transBinds = append(transBinds, m)
			continue
		}
		chroot := hostRoot + p.config.Root
		exists, err := existsInChroot(chroot, m.EffectiveSource)
		if err != nil {
			logrus.Errorf("error chrooting to/from %s: %s", chroot, err)
		}
		if !exists {
			logrus.Infof("host path %s doesn't exist", m.EffectiveSource)
			// maybe it's a VM path
			exists, err = existsInChroot(hostRoot, m.EffectiveSource)
			if err != nil {
				logrus.Errorf("error chrooting to/form %s: %s", hostRoot, err)
			}
			if !exists {
				logrus.Infof("VM path %s doesn't exist: %s", m.EffectiveSource)
				transBinds = append(transBinds, m)
			} else {
				transBinds = append(transBinds, nil)
			}
		} else {
			transBinds = append(transBinds, m)
		}
	}

	return transBinds
}

func existsInChroot(chroot, path string) (bool, error) {
	if err := syscall.Chroot(chroot); err != nil {
		return false, err
	}
	_, statErr := os.Stat(path)
	err := syscall.Chroot(".")
	return !os.IsNotExist(statErr), err
}

func filterNils(list []*mountpoint.MountPoint) []*mountpoint.MountPoint {
	filtered := make([]*mountpoint.MountPoint, 0)
	for _, el := range list {
		if el != nil {
			filtered = append(filtered, el)
		}
	}
	return filtered
}

func (p transbindPlugin) Detach(req mountpoint.DetachRequest) mountpoint.DetachResponse {
	resp, err := post(p.httpClient, "http://server/TransbindPlugin.MountPointDetach", req)
	if err != nil {
		return mountpoint.DetachResponse{
			Success:     false,
			Recoverable: false,
			Err:         fmt.Sprintf("Error posting detach to transbind server: %s", err),
		}
	}

	var detachResponse mountpoint.DetachResponse

	if err = json.Unmarshal(resp, &detachResponse); err != nil {
		return mountpoint.DetachResponse{
			Success:     false,
			Recoverable: false,
			Err:         fmt.Sprintf("Error parsing detach response from transbind server: %s", err),
		}
	}

	return detachResponse
}

func (p transbindPlugin) Properties(req mountpoint.PropertiesRequest) mountpoint.PropertiesResponse {
	typeBind := mountpoint.TypeBind
	typeVolume := mountpoint.TypeVolume

	logrus.Info("got properties request")

	return mountpoint.PropertiesResponse{
		Success: true,
		Patterns: []mountpoint.Pattern{
			{Type: &typeBind},
			{
				Type: &typeVolume,
				Volume: mountpoint.VolumePattern{
					Driver: []mountpoint.StringPattern{
						{Exactly: "local"},
					},
					Options: []mountpoint.StringMapPattern{{
						Exists: []mountpoint.StringMapKeyValuePattern{
							{
								Key:   mountpoint.StringPattern{Exactly: "o"},
								Value: mountpoint.StringPattern{Contains: "bind"},
							},
							{
								Key:   mountpoint.StringPattern{Exactly: "device"},
								Value: mountpoint.StringPattern{PathPrefix: p.config.Root},
							},
						},
					}},
				},
			},
		},
	}
}

func checkRoot(root string) error {
	// check we can open the root path
	rootDir, err := os.Open(root)
	if err != nil {
		return err
	}
	defer rootDir.Close()

	// ... and it's a directory
	_, err = rootDir.Readdir(1)
	if err != nil && err != io.EOF {
		return err
	}

	return nil
}

func post(client *http.Client, path string, obj interface{}) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})
	jsonEncoder := json.NewEncoder(buf)
	err := jsonEncoder.Encode(obj)
	if err != nil {
		return []byte{}, err
	}

	resp, err := client.Post(path, pluginContentType, buf)
	if err != nil {
		return []byte{}, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return []byte{}, errOfResponse(resp)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}
	return body, nil
}

func errOfResponse(resp *http.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("error reading server response", resp.Status))
	}
	return fmt.Errorf("error posting to server: %s: %s", resp.Status, body)
}

func dialSock(sockName string) (net.Conn, error) {
	pieces := strings.SplitN(sockName, ":", 2)
	if len(pieces) > 1 {
		switch pieces[0] { // socket type
		case "vsock":
			return dialVsock(pieces[1])
		default:
			return nil, fmt.Errorf("unknown socket type '%s'", pieces[0])
		}
	}
	return nil, errors.New("no socket type specified")
}

func dialVsock(address string) (net.Conn, error) {
	var cid64 uint64
	var port64 uint64
	var err error
	pieces := strings.SplitN(address, ":", 2)
	if len(pieces) > 1 {
		if pieces[0] == "_" {
			cid64 = uint64(^uint32(0))
		} else {
			cid64, err = strconv.ParseUint(pieces[0], 10, 32)
			if err != nil {
				return nil, err
			}
		}

		port64, err = strconv.ParseUint(pieces[1], 10, 32)
		if err != nil {
			return nil, err
		}

		return vsock.Dial(uint32(cid64), uint32(port64))
	}
	return nil, errors.New("vsock port missing")
}
