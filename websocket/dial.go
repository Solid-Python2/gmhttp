/*
 * @Description:
 * @Version: 1.0
 * @Autor: solid
 * @Date: 2022-02-09 16:48:04
 * @LastEditors: solid
 * @LastEditTime: 2022-02-09 17:34:05
 */
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"fmt"
	"net"

	"github.com/OblivionTime/gmhttp/tls"
)

func dialWithDialer(dialer *net.Dialer, config *Config) (conn *tls.Conn, err error) {
	fmt.Println(parseAuthority(config.Location))
	switch config.Location.Scheme {
	case "wss":
		conn, err = tls.DialWithDialer(dialer, "tcp", parseAuthority(config.Location), config.TlsConfig)
	default:
		err = ErrBadScheme
	}
	return
}
