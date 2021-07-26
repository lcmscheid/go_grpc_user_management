package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	pb "example.com/our_project/src/api"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type server struct{}

var collection *mongo.Collection

var (
	port    = ":50051"
	crtFile = "certs/server.crt" //filepath.Join("certs", "server.crt")
	keyFile = "certs/server.pem" //filepath.Join("certs", "server.key")
	caFile  = filepath.Join("certs", "ca.crt")
)

type userItem struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Password  string             `bson:"password"`
	FirstName string             `bson:"first_name"`
	LastName  string             `bson:"last_name"`
	Email     string             `bson:"email"`
	Phone     string             `bson:"phone"`
	Gender    pb.Gender          `bson:"gender"`
	Birthday  string             `bson:"birthday"`
}

func main() {
	// if we crash the go code, we get the file name and the line number
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Println("Starting server...")

	// connect to mongoDB
	log.Println("Connecting to mongoDB")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	db, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}

	collection = db.Database("mydb").Collection("user")

	log.Printf("crtFile: %v", crtFile)
	certificate, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load key pair: %s\n", err)
	}

	// Create a certificate pool from the certificate authority
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("could not read ca certificates: %s\n", err)
	}

	// Append the client certificates from the CA
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalln("failed to append client certs")
	}

	opts := []grpc.ServerOption{
		// Enable TLS for all incoming connections.
		grpc.Creds( // Create the TLS credentials
			credentials.NewTLS(&tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{certificate},
				ClientCAs:    certPool,
			},
			)),
	}

	s := grpc.NewServer(opts...)
	pb.RegisterUserManagementServer(s, &server{})

	// register reflection service on gRPC server
	reflection.Register(s)

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v\n", err)
	}

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v\n", err)
		}
	}()

	// wait for Ctrl+c to exit
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)

	// block until a signal is received
	<-ch
	log.Println("Stopping the server")
	s.Stop()
	log.Println("Closing the listener")
	lis.Close()
	log.Println("End of Service")
}

func (*server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	user := req.GetUser()
	data := userItem{
		Password:  user.GetPassword(),
		FirstName: user.GetFirstName(),
		LastName:  user.GetLastName(),
		Email:     user.GetEmail(),
		Phone:     user.GetPhone(),
		Gender:    user.GetGender(),
		Birthday:  user.GetBirthday(),
	}

	res, err := collection.InsertOne(context.Background(), data)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal,
			fmt.Sprintf("Internal error: %v\n", err),
		)
	}

	oid, ok := res.InsertedID.(primitive.ObjectID)
	if !ok {
		return nil, status.Errorf(
			codes.Internal,
			fmt.Sprintln("Cannot convert to OID"),
		)
	}

	return &pb.CreateUserResponse{
		User: &pb.User{
			Id:        oid.Hex(),
			FirstName: user.GetFirstName(),
			LastName:  user.GetLastName(),
			Email:     user.GetEmail(),
			Phone:     user.GetPhone(),
			Gender:    user.GetGender(),
			Birthday:  user.GetBirthday(),
		},
	}, nil
}

func (*server) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error) {
	user := req.GetUser()
	oid, err := primitive.ObjectIDFromHex(user.GetId())
	if err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument,
			fmt.Sprintf("Cannot parse ID: %v\n", err),
		)
	}

	data := &userItem{}
	filter := bson.D{{Key: "_id", Value: oid}}
	res := collection.FindOne(context.Background(), filter)
	if err := res.Decode(data); err != nil {
		return nil, status.Errorf(
			codes.NotFound,
			fmt.Sprintf("Cannot find user with specified ID: %v\n", oid),
		)
	}

	// update user
	data.Password = user.GetPassword()
	data.FirstName = user.GetFirstName()
	data.LastName = user.GetLastName()
	data.Email = user.GetEmail()
	data.Phone = user.GetPhone()
	data.Gender = user.GetGender()
	data.Birthday = user.GetBirthday()

	_, err = collection.ReplaceOne(context.Background(), filter, data)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal,
			fmt.Sprintf("Cannot update user in MongoDB: %v\n", err),
		)
	}

	return &pb.UpdateUserResponse{
		User: dataToUserPb(data),
	}, nil
}

func (*server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	oid, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument,
			fmt.Sprintf("Cannot parse ID: %v\n", err),
		)
	}

	// create an empty struct
	data := &userItem{}
	res := collection.FindOne(context.Background(), bson.D{{Key: "_id", Value: oid}})
	if err := res.Decode(data); err != nil {
		return nil, status.Errorf(
			codes.NotFound,
			fmt.Sprintf("Cannot find user with specified ID: %v\n", oid),
		)
	}

	return &pb.GetUserResponse{
		User: dataToUserPb(data),
	}, nil
}

func (*server) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	oid, err := primitive.ObjectIDFromHex(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(
			codes.InvalidArgument,
			fmt.Sprintf("Cannot parse ID: %v\n", err),
		)
	}

	filter := bson.D{{Key: "_id", Value: oid}}
	res, err := collection.DeleteOne(context.Background(), filter)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal,
			fmt.Sprintf("Cannot delete user in MongoDB: %v\n", err),
		)
	}

	if res.DeletedCount == 0 {
		return nil, status.Errorf(
			codes.NotFound,
			fmt.Sprintf("Cannot find user with specified ID: %v\n", oid),
		)
	}

	return &pb.DeleteUserResponse{UserId: req.GetUserId()}, nil
}

func (*server) ListUsers(req *pb.ListUsersRequest, stream pb.UserManagement_ListUsersServer) error {
	cur, err := collection.Find(context.Background(), bson.M{})
	if err != nil {
		return status.Errorf(
			codes.Internal,
			fmt.Sprintf("Unknown internal error while querrying all users from mongoDB: %v\n", err),
		)
	}

	defer cur.Close(context.Background())

	for cur.Next(context.Background()) {
		data := &userItem{}
		if err := cur.Decode(data); err != nil {
			return status.Errorf(
				codes.Internal,
				fmt.Sprintf("Error while decoding user data from mongoDB: %v\n", err),
			)
		}
		stream.Send(&pb.ListUsersResponse{User: dataToUserPb(data)})
	}
	if err := cur.Err(); err != nil {
		return status.Errorf(
			codes.Internal,
			fmt.Sprintf("Unknown internal error while iteratingg over user list cursor: %v", err),
		)
	}
	return nil
}

func dataToUserPb(data *userItem) *pb.User {
	return &pb.User{
		Id:        data.ID.Hex(),
		Password:  data.Password,
		FirstName: data.FirstName,
		LastName:  data.LastName,
		Email:     data.Email,
		Phone:     data.Phone,
		Gender:    data.Gender,
		Birthday:  data.Birthday,
	}
}
