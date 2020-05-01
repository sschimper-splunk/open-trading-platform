package main

import (
	"context"
	"fmt"
	"github.com/ettec/open-trading-platform/go/common/bootstrap"
	"github.com/ettec/open-trading-platform/go/common/k8s"
	"github.com/ettec/open-trading-platform/go/model"
	"github.com/ettech/open-trading-platform/go/market-data-service/api"
	"github.com/ettech/open-trading-platform/go/market-data-service/marketdatasource"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logger "log"
	"net"
	"os"
	"strconv"
	"time"
)

type service struct {
	micToSource map[string]*marketdatasource.MdsConnection
}

func (s *service) Subscribe(_ context.Context, r *api.MdsSubscribeRequest) (*model.Empty, error) {

	mic := r.Listing.Market.Mic
	if source, ok := s.micToSource[mic]; ok {
		if conn, ok := source.GetConnection(r.SubscriberId); ok {

			if err := conn.Subscribe(r.Listing.Id); err != nil {
				return nil, err
			}

			return &model.Empty{}, nil
		} else {
			return nil, fmt.Errorf("failed  to subscribe, no connection exists for subscriber " + r.SubscriberId)
		}

	} else {
		return nil, fmt.Errorf("no market data source exists for mic %v", mic)
	}

}

func (s *service) Connect(request *api.MdsConnectRequest, stream api.MarketDataService_ConnectServer) error {

	subscriberId := request.GetSubscriberId()

	log.Println("connect request received for subscriber ", subscriberId)

	out := make(chan *model.ClobQuote, 100)

	for mic, gateway := range s.micToSource {
		gateway.AddConnection(subscriberId, out)
		log.Printf("connected subscriber %v to market data source for mic %ve", subscriberId, mic)
	}

	for mdUpdate := range out {
		if err := stream.Send(mdUpdate); err != nil {
			log.Printf("error on connection for subscriber %v, closing connection, error:%v", subscriberId, err)
			break
		}
	}

	return nil
}

const (
	ServiceIdKey        = "SERVICE_ID"
	ConnectRetrySeconds = "CONNECT_RETRY_SECONDS"
	External            = "EXTERNAL"
)

var maxSubscriptions = 10000

var log = logger.New(os.Stdout, "", logger.Ltime|logger.Lshortfile)
var errLog = logger.New(os.Stderr, "", logger.Ltime|logger.Lshortfile)

func main() {

	id := bootstrap.GetEnvVar(ServiceIdKey)

	connectRetrySecs := bootstrap.GetOptionalIntEnvVar(ConnectRetrySeconds, 60)

	external := bootstrap.GetOptionalBoolEnvVar(External, false)

	mdService := service{micToSource: map[string]*marketdatasource.MdsConnection{}}

	clientSet := k8s.GetK8sClientSet(external)

	namespace := "default"
	list, err := clientSet.CoreV1().Services(namespace).List(v1.ListOptions{
		LabelSelector: "app=market-data-source",
	})

	if err != nil {
		panic(err)
	}

	log.Printf("found %v market data sources", len(list.Items))

	for _, service := range list.Items {
		const micLabel = "mic"
		if _, ok := service.Labels[micLabel]; !ok {
			errLog.Printf("ignoring market data source as it does not have a mic label, service: %v", service)
			continue
		}

		mic := service.Labels[micLabel]

		var podPort int32
		for _, port := range service.Spec.Ports {
			if port.Name == "api" {
				podPort = port.Port
			}
		}

		if podPort == 0 {
			log.Printf("ignoring market data service as it does not have a port named api, service: %v", service)
			continue
		}

		targetAddress := service.Name + ":" + strconv.Itoa(int(podPort))

		client, err := marketdatasource.NewMdsConnection(id, targetAddress, time.Duration(connectRetrySecs)*time.Second,
			maxSubscriptions)
		if err != nil {
			errLog.Printf("failed to create connection to market data source at %v, error: %v", targetAddress, err)
			continue
		}

		mdService.micToSource[mic] = client

		log.Printf("added market data source for mic: %v, service name: %v, target address: %v", mic, service.Name, targetAddress)
	}

	port := "50551"
	fmt.Println("Starting Market Data Service on port:" + port)
	lis, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("Error while listening : %v", err)
	}

	s := grpc.NewServer()
	if err != nil {
		log.Panicf("failed to create market data service:%v", err)
	}

	api.RegisterMarketDataServiceServer(s, &mdService)

	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Error while serving : %v", err)
	}

}
