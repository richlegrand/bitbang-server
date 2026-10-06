// Package settings is the device settings page: the *settings meta-page, and
// the panel a device page embeds with data-bitbang-page="settings".
//
// Today its server part is serving those two files: every setting comes from
// the device, over the data channel, and every write goes back to it. What
// plugin-model.md gives this plugin beyond that -- delivering other plugins'
// device_settings schemas in `registered`, and keeping the copy of their values
// the device syncs -- arrives with the first plugin that declares any, which is
// notify's Telegram.
package settings

import "bitbang-server-go/internal/plugin"

type Plugin struct{}

func (Plugin) Name() string { return "settings" }

func (Plugin) Init(h plugin.Host) error {
	if err := h.MetaPage("settings"); err != nil {
		return err
	}
	return h.Panel("settings")
}
