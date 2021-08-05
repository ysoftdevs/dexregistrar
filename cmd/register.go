/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"strconv"
	"strings"

	"github.com/dexidp/dex/api/v2"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "registers DEX client",
	Long:  `Registers dex client fot openID purposes`,
	Run: func(cmd *cobra.Command, args []string) {
		registerDexClient()
	},
}

var host string
var port int
var caPath string
var clientCert string
var clientKey string
var clientId string
var clientSecret string
var redirectUris []string

func init() {
	rootCmd.AddCommand(registerCmd)

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// registerCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	registerCmd.Flags().StringVarP(&host, "address", "a", "localhost", "Hostname address to connect to")
	_ = registerCmd.MarkFlagRequired("address")
	registerCmd.Flags().IntVarP(&port, "port", "p", 5557, "Host port to connect to")
	_ = registerCmd.MarkFlagRequired("port")
	registerCmd.Flags().StringVarP(&caPath, "cacertpath", "t", "/etc/dex/ca.crt", "Path to client CA cert to connect to")
	_ = registerCmd.MarkFlagRequired("cacertpath")
	registerCmd.Flags().StringVarP(&clientCert, "clientCert", "e", "", "Path to client cert for mTLS")
	registerCmd.Flags().StringVarP(&clientKey, "clientKey", "k", "", "Path to client key for mTLS")

	registerCmd.Flags().StringVarP(&clientId, "clientid", "c", "", "ClientID to register")
	_ = registerCmd.MarkFlagRequired("clientid")
	registerCmd.Flags().StringVarP(&clientSecret, "clientsecret", "s", "", "ClientSecret to register")
	_ = registerCmd.MarkFlagRequired("clientsecret")
	registerCmd.Flags().StringArrayVarP(&redirectUris, "redirecturis", "r", nil, "RedirectURIs to register")
	_ = registerCmd.MarkFlagRequired("redirecturis")
}

func newDexClient(hostAndPort string) (api.DexClient, error) {
	//---------- TLS Setting -----------//
	clientCertificate, err := tls.LoadX509KeyPair(
		clientCert,
		clientKey,
	)
	if err != nil {
		log.Fatalf("failed to read client cert or key: %s", err)
	}
	serverCertPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.Fatalf("failed to read ca cert: %s", err)
	}

	ok := serverCertPool.AppendCertsFromPEM(bs)
	if !ok {
		log.Fatal("failed to append certs")
	}
	var transportCreds credentials.TransportCredentials
	if clientCert != "" {
		transportCreds = credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{clientCertificate},
			RootCAs:      serverCertPool,
		})
	} else {
		transportCreds = credentials.NewTLS(&tls.Config{
			RootCAs: serverCertPool,
		})
	}

	conn, err := grpc.Dial(hostAndPort, grpc.WithTransportCredentials(transportCreds))
	if err != nil {
		return nil, fmt.Errorf("dial: %v", err)
	}
	return api.NewDexClient(conn), nil
}

func registerDexClient() {
	client, err := newDexClient(strings.Join([]string{host, strconv.Itoa(port)}, ":"))
	if err != nil {
		log.Fatalf("failed creating dex client: %v ", err)
	}

	req := &api.CreateClientReq{
		Client: &api.Client{
			Id:           clientId,
			Name:         clientId,
			Secret:       clientSecret,
			RedirectUris: redirectUris,
		},
	}

	createClientResponse, err := client.CreateClient(context.TODO(), req)
	if err != nil {
		log.Fatalf("failed creating oauth2 client: %v", err)
	}

	if !createClientResponse.AlreadyExists {
		return
	}

	updateReq := &api.UpdateClientReq{
		Id:           req.Client.Id,
		Name:         req.Client.Name,
		RedirectUris: req.Client.RedirectUris,
	}

	if _, err := client.UpdateClient(context.TODO(), updateReq); err != nil {
		log.Fatalf("failed updating oauth2 client %v", err)
	}
}
