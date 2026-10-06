// Package ota is the device firmware page: the *ota meta-page.
//
// The page asks the device what it is running and streams an image to it,
// both over the data channel, so the server's part is serving the one file.
// ota-mock.json beside it in web/plugins/ota/ is for working on the page with
// no device, and is not registered.
package ota

import "bitbang-server-go/internal/plugin"

type Plugin struct{}

func (Plugin) Name() string { return "ota" }

func (Plugin) Init(h plugin.Host) error {
	return h.MetaPage("ota")
}
