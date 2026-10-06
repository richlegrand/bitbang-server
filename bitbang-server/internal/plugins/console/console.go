// Package console is the device console: the *console meta-page, and the
// panel a device page embeds with data-bitbang-page="console".
//
// All of it runs in the browser. The log arrives over the device's data
// channel, end to end, and the server never sees a byte of it -- so the
// server's whole part is serving the two files. That is why it was the first
// thing moved out of the core: a plugin with no server behavior proves the
// plumbing without depending on any.
//
// The panel imports panel-fold.js and setting-control.js, which the settings
// panel imports too. They stay in the core, a small shared kit for panels,
// rather than belonging to either plugin.
package console

import "bitbang-server-go/internal/plugin"

type Plugin struct{}

func (Plugin) Name() string { return "console" }

func (Plugin) Init(h plugin.Host) error {
	if err := h.MetaPage("console"); err != nil {
		return err
	}
	return h.Panel("console")
}
