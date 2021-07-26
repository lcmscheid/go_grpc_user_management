module example.com/our_project

go 1.16

require (
	go.mongodb.org/mongo-driver v1.5.4
	google.golang.org/grpc v1.39.0
	google.golang.org/protobuf v1.27.1
)

replace example.com/our_project => ../our_project
