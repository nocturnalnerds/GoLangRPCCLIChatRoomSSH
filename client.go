package main

import (
	pb "GOCLIAPP/chatpb"
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
)

func flushPrint(s string) {
  fmt.Print(s); os.Stdout.Sync()
}

func savePriv(name string, priv ed25519.PrivateKey) {
  data := base64.StdEncoding.EncodeToString(priv)
  os.WriteFile(".key_"+name, []byte(data), 0600)
}

func loadPriv(name string) ed25519.PrivateKey {
  data, err := os.ReadFile(".key_" + name)
  if err != nil {
    return nil
  }
  raw, err := base64.StdEncoding.DecodeString(string(data))
  if err != nil {
    return nil
  }
  return ed25519.PrivateKey(raw)
}

func register(client pb.ChatServiceClient, rd *bufio.Reader) (string, ed25519.PrivateKey) {
	flushPrint("Register username: ")
	name, _ := rd.ReadString('\n')
	name = strings.TrimSpace(name)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	resp, err := client.Register(context.Background(), &pb.RegisterRequest{
		Name:   name,
		Pubkey: pub,
	})
	if err != nil || !resp.Success {
		log.Fatalf("Register failed: %v | %s", err, resp.Message)
	}

	encodedPriv := base64.StdEncoding.EncodeToString(priv)
	fmt.Println("Registered successfully!")
	fmt.Printf("Your private key (keep this safe!):\n%s\n", encodedPriv)

	return name, priv
}

func login(client pb.ChatServiceClient, rd *bufio.Reader) (string, ed25519.PrivateKey) {
	flushPrint("Login username: ")
	name, _ := rd.ReadString('\n')
	name = strings.TrimSpace(name)

	flushPrint("Paste your private key (base64): ")
	privStr, _ := rd.ReadString('\n')
	privStr = strings.TrimSpace(privStr)

	raw, err := base64.StdEncoding.DecodeString(privStr)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		log.Fatalf("Invalid private key.")
	}
	priv := ed25519.PrivateKey(raw)

	resp, err := client.Login(context.Background(), &pb.LoginRequest{Name: name})
	if err != nil || !resp.Success {
		log.Fatalf("Login failed: %v | %s", err, resp.Message)
	}

	sig := ed25519.Sign(priv, resp.Nonce)
	vresp, err := client.Verify(context.Background(), &pb.VerifyRequest{Name: name, Signed: sig})
	if err != nil || !vresp.Success {
		log.Fatalf("Verify failed: %v | %s", err, vresp.Message)
	}

	fmt.Println("Logged in")
	return name, priv
}


func main() {
  conn, err := grpc.Dial("turntable.proxy.rlwy.net:34757", grpc.WithInsecure())
  if err != nil {
    log.Fatalf("Connect error: %v", err)
  }
  defer conn.Close()
  client := pb.NewChatServiceClient(conn)
  rd := bufio.NewReader(os.Stdin)

  var username string
  for {
    flushPrint("[L]ogin or [R]egister? ")
    cmd, _ := rd.ReadString('\n'); cmd = strings.ToLower(strings.TrimSpace(cmd))
    if cmd == "r" {
      username, _ = register(client, rd)
      break
    } else if cmd == "l" {
      username, _ = login(client, rd)
      break
    }
  }

  channel := "main"
  stream, err := client.Join(context.Background(), &pb.User{Name: username, Channel: channel})
  if err != nil {
    log.Fatalf("Join error: %v", err)
  }

  fmt.Printf("Welcome %s! You are in [%s]\n", username, channel)
  client.SendMessage(context.Background(), &pb.Message{
    User: username, Text: fmt.Sprintf("%s joined", username),
    Timestamp: time.Now().Unix(), Channel: channel,
  })

  fmt.Println(`
Available commands:
/help                Show this help message
/msg <user> <msg>    Send a private message
/create <room>       Create a new chat room
/switch <room>       Switch to another chat room
/exit                Exit the chat

Just type your message and press Enter to chat in the current room.`)

  go func() {
    for {
      m, err := stream.Recv()
      if err != nil {
        log.Fatalf("Recv error: %v", err)
      }
      if m.Receiver == username {
        fmt.Printf("[Private] %s: %s\n", m.User, m.Text)
      } else if m.Receiver == "" && m.Channel == channel && m.User != username{
        fmt.Printf("[%s] %s\n", m.User, m.Text)
      }
    }
  }()

  for {
    text, _ := rd.ReadString('\n'); text = strings.TrimSpace(text)
    if text == "" {
      continue
    }
    if strings.HasPrefix(text, "/") {
      parts := strings.SplitN(text, " ", 3)
      switch parts[0] {
      case "/exit":
        fmt.Println("Exiting...")
        client.SendMessage(context.Background(), &pb.Message{
          User:      username,
          Text:      fmt.Sprintf("%s has left the chat.", username),
          Timestamp: time.Now().Unix(),
          Channel:   channel,
        })
        os.Exit(0)
      case "/msg":
        if len(parts) < 3 {
          fmt.Println("Usage: /msg <user> <message>")
          continue
        }
        receiver, message := parts[1], parts[2]
        if(receiver == username){
          fmt.Println("Cant send to your self!");
          continue;
        }
        client.SendMessage(context.Background(), &pb.Message{
          User:      username,
          Text:      message,
          Timestamp: time.Now().Unix(),
          Receiver:  receiver,
          Channel:   channel,
        })
        fmt.Printf("[Private to %s]: %s\n", receiver, message)

      case "/create":
        if len(parts) < 2 {
          fmt.Println("Usage: /create <room>")
          continue
        }
        room := parts[1]
        resp, err := client.CreateRoom(context.Background(), &pb.RoomRequest{Name: room})
        if err != nil {
          fmt.Println("Room creation failed:", err)
        } else if resp.AlreadyExists {
          fmt.Println("Room already exists.")
        } else {
          fmt.Printf("Room '%s' created.\n", room)
        }

      case "/switch":
        if len(parts) < 2 {
          fmt.Println("Usage: /switch <room>")
          continue
        }
        newRoom := parts[1]
        _, err := client.SwitchChannel(context.Background(), &pb.User{Name: username, Channel: newRoom})
        if err != nil {
          fmt.Println("Room switch failed:", err)
          continue
        }
        channel = newRoom
        fmt.Printf("Switched to [%s]\n", channel)
        client.SendMessage(context.Background(), &pb.Message{
          User:      username,
          Text:      fmt.Sprintf("%s has joined room '%s'", username, channel),
          Timestamp: time.Now().Unix(),
          Channel:   channel,
        })
      case "/help":
        fmt.Println(`
Available commands:
/help                Show this help message
/msg <user> <msg>    Send a private message
/create <room>       Create a new chat room
/switch <room>       Switch to another chat room
/exit                Exit the chat

Just type your message and press Enter to chat in the current room.`)
      default:
        flushPrint("Unknow Command!");
      }
      continue
    }
    client.SendMessage(context.Background(), &pb.Message{
      User: username, Text: text,
      Channel: channel, Timestamp: time.Now().Unix(),
    })
  }
}
