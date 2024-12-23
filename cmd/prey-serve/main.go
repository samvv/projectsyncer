package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/google/shlex"
	"golang.org/x/crypto/ssh"
)

const REPO_OBJECT_CACHE_SIZE = 1024

type App struct {
	fs       billy.Filesystem
	cache    cache.Object
	repoPath string
	storers  map[string]storer.Storer
}

func NewApp(repoPath string) App {
	return App{
		osfs.New(repoPath),
		cache.NewObjectLRU(REPO_OBJECT_CACHE_SIZE),
		repoPath,
		make(map[string]storer.Storer),
	}
}

func (app App) Load(ep *transport.Endpoint) (storer.Storer, error) {
	s, ok := app.storers[ep.String()]
	if !ok {
		return nil, transport.ErrRepositoryNotFound
	}
	return s, nil
}

func (app App) AddRepo(name string) error {
	storer := filesystem.NewStorage(app.fs, app.cache)
	app.storers[name] = storer
	return nil
}

type Client struct {
	app App
	tcpConn net.Conn
	sshConn *ssh.ServerConn
}

func main() {

	repoPath := "./repositories" // Directory to store repositories
	err := os.MkdirAll(repoPath, 0700)
	if err != nil {
		log.Fatalf("Failed to create repository directory: %v", err)
	}

	privateKeyPath := "./id_rsa" // Path to SSH private key
	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true, // For demo purposes; use proper authentication in production.
	}

	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	sshConfig.AddHostKey(private)

	address := "localhost:2222"
	app := NewApp(repoPath)

	log.Printf("SSH Git server is running at ssh://%s\n", address)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", address, err)
	}
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %s", err)
			continue
		}
		// FIXME DOS attack possible due to NewServerConn being blocking
		sshConn, channels, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			tcpConn.Close()
			log.Printf("Failed to perform SSH handshake: %s", err)
			continue
		}
		client := Client { app, tcpConn, sshConn }
		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go client.handleChannels(channels)
	}
}

var allowed = map[string]struct {} {
	"git-upload-pack": {},
	"git-upload-archive": {},
	"git-receive-pack": {},
}

func (client Client) handleChannels(channels <-chan ssh.NewChannel) {

	defer func () { log.Println("CLOSING TCP"); log.Printf("%s", client.tcpConn.Close()) }()
	defer func () { log.Println("CLOSING SSH"); log.Printf("%s", client.sshConn.Close()) }()

	var wg sync.WaitGroup 

	for newChannel := range channels {

		wg.Add(1)

		go func() {

			defer wg.Done()

			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
				return
			}

			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Printf("Could not accept channel: %s", err)
				return
			}
			defer func () { log.Printf("CLOSING CHANNEL: %s", channel.Close()); }()

			for req := range requests {

				switch (req.Type) {

				case "exec":

					argv, err := shlex.Split(string(req.Payload[4:]))
					if err != nil {
						req.Reply(false, nil)
						continue
					}
					if len(argv) < 2 {
						req.Reply(false, nil)
						continue
					}

					cmdName := argv[0]
					repoId := argv[1]

					_, ok := allowed[cmdName]
					if ! ok {
						log.Printf("Client trying to run '%s', which is not a supported command", cmdName)
						channel.Stderr().Write([]byte(fmt.Sprintf("'%s' is not a supported command\n", cmdName)))
						req.Reply(false, nil)
						continue
					}

					repoPath := filepath.Join(client.app.repoPath, repoId)

					req.Reply(true, nil)
					log.Print("REPLIED")

					cmd := exec.Command(cmdName, ".")
					cmd.Dir = repoPath
					cmd.Env = []string {} // For security reasons

					cmd.Stdin = channel
					cmd.Stdout = channel
					cmd.Stderr = os.Stderr

					// err = cmd.Run()
					// if err != nil {
					// 	channel.Stderr().Write([]byte("Internal server error. Try again later. Administrators should read the logs.\n"))
					// 	log.Printf("Failed to run '%s': %s", cmdName, err)
					// 	req.Reply(false, nil)
					// 	continue
					// }

					// // Use pipes instead of directly attaching to the channel
					// stdinPipe, err := cmd.StdinPipe()
					// if err != nil {
					// 	log.Printf("Failed to create stdin pipe: %v", err)
					// 	req.Reply(false, nil)
					// 	return
					// }
					// stdoutPipe, err := cmd.StdoutPipe()
					// if err != nil {
					// 	log.Printf("Failed to create stdout pipe: %v", err)
					// 	req.Reply(false, nil)
					// 	return
					// }
					// stderrPipe, err := cmd.StderrPipe()
					// if err != nil {
					// 	log.Printf("Failed to create stderr pipe: %v", err)
					// 	req.Reply(false, nil)
					// 	return
					// }

					// // Start the command
					// if err := cmd.Start(); err != nil {
					// 	log.Printf("Failed to start command: %v", err)
					// 	req.Reply(false, nil)
					// 	return
					// }

					// // Send success reply to the SSH client
					// req.Reply(true, nil)

					// // Forward data between the SSH channel and the command
					// go func() {
					// 	// defer stdinPipe.Close()
					// 	if _, err := io.Copy(stdinPipe, channel); err != nil {
					// 		log.Printf("Failed to copy input to command: %v", err)
					// 	}
					// }()

					// go func() {
					// 	// defer stdoutPipe.Close()
					// 	if _, err := io.Copy(channel, stdoutPipe); err != nil {
					// 		log.Printf("Failed to copy output from command: %v", err)
					// 	}
					// }()

					// go func() {
					// 	// defer stderrPipe.Close()
					// 	if _, err := io.Copy(channel.Stderr(), stderrPipe); err != nil {
					// 		log.Printf("Failed to copy stderr from command: %v", err)
					// 	}
					// }()

					// // Wait for the command to complete
					// if err := cmd.Wait(); err != nil {
					// 	log.Printf("Command failed: %v", err)
					// }

					return

				case "shell":
					channel.Stderr().Write([]byte("You are trying to open a shell on a Git server, which is not supported.\n"))
					req.Reply(false, nil)
					log.Println("Client requested interactive session, which is not supported.")
					return

				default:
					channel.Stderr().Write([]byte("Unsupported protocol feature. Exiting.\n"))
					req.Reply(false, nil)
					log.Printf("Client send an unknown SSH request type: %s", req.Type)
					return

				}

			}

		}()

	}

	wg.Wait()

}

func handleChannel(newChannel ssh.NewChannel, app App) {
}
