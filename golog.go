package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"
    "github.com/msbranco/goconfig"
)

const GOLOG_VERSION = "0.0.1"

type Input struct {
    name string
    parameters map[string] interface {}
}

func (input Input) to_json() string {
    result, err := json.Marshal(input.parameters)
    log.Println(err)
    if err != nil {
        m := make(map[string]string)
        result, err = json.Marshal(m)
    }
    return string(result)
}

type Event struct {
    name string
    create_at time.Time
}

type Configuration struct {
    inputs map[string]Input
}

func read_tcp_from_config(section string, config *goconfig.ConfigFile) (Input, error) {
    input := Input{name:"tcp", parameters: make(map[string] interface{})}

    _type, _ := config.GetString(section, "type")
    input.parameters["type"] = _type

    port, _ := config.GetInt64(section, "port")
    input.parameters["port"] = int(port)

    hostname, _ := config.GetString(section, "hostname")
    input.parameters["hostname"] = hostname

    ssl_enable, _ := config.GetBool(section, "ssl_enable")
    input.parameters["ssl_enable"] = ssl_enable

    return input, nil
}

func NewInput(name string) Input {
    return Input{name:name, parameters: make(map[string] interface{})}
}

func read_udp_from_config(section string, config *goconfig.ConfigFile) (Input, error) {
    input := NewInput("udp")

    _type, _ := config.GetString(section, "type")
    input.parameters["type"] = _type

    port, _ := config.GetInt64(section, "port")
    input.parameters["port"] = int(port)

    hostname, _ := config.GetString(section, "hostname")
    input.parameters["hostname"] = hostname

    return input, nil
}

func read_config(filename string) (*Configuration, error) {
    config, err := goconfig.ReadConfigFile(filename)
    if err != nil {
        log.Panic(err)
        return nil, err
    }

    configuration := &Configuration{}

    inputs, err := config.GetString("general", "inputs")
    if err != nil {
        log.Panic(err)
        return nil, err
    }

    configuration.inputs = make(map[string] Input)

    for _, input_iter := range strings.Split(inputs, ",") {
        input_iter := strings.TrimSpace(input_iter)

        if input_iter == "tcp" {
            section := fmt.Sprintf("input:%s", input_iter)
            input, _ := read_tcp_from_config(section, config)
            key := fmt.Sprintf("%s:%s", input_iter, input.parameters["type"])
            configuration.inputs[key] = input
        } else if input_iter == "udp" {
            section := fmt.Sprintf("input:%s", input_iter)
            input, _ := read_udp_from_config(section, config)
            key := fmt.Sprintf("%s:%s", input_iter, input.parameters["type"])
            configuration.inputs[key] = input
        }
    }

    return configuration, nil
}

func launchTcpServer(host string, port int) {
    iface := fmt.Sprintf("%s:%d", host, port)
    listener, err := net.Listen("tcp", iface)
    log.Println("Listening at tcp://" + iface)

    if err != nil {
        log.Panic(err)
    }
    defer listener.Close()

    for {
        client, err := listener.Accept()
        if err != nil {
            log.Panic(err)

        }
        go serveTcpClient(client)

    }
}

func serveTcpClient(conn net.Conn) {
    defer conn.Close()
    log.Println("Test")
}

func launchUdpServer(host string, port int) {
    iface := fmt.Sprintf("%s:%d", host, port)
    udp_addr, _ := net.ResolveUDPAddr("udp4", iface)
    listener, err := net.ListenUDP("udp", udp_addr)
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()
    log.Println("Listening at udp://"+ iface)

    for {
        var buffer [512] byte
        recv_bytes, addr, err := listener.ReadFromUDP(buffer[0:])
        if err != nil {
            log.Fatal(err)
        }
        log.Println(addr)
        log.Println(recv_bytes)
        log.Println(buffer)
    }
}

func main() {
    sigs := make(chan os.Signal, 1)
    done := make(chan bool, 1)

    log.Printf("golog - version %s", GOLOG_VERSION)
    log.Printf("Process ID: %d", os.Getpid())

    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        sig := <-sigs
        log.Println(sig)
        done <- true
    }()

    configuration, err := read_config("golog.cfg")
    if err != nil {
        log.Panic(err)
        os.Exit(1)
    }

    for itype, input := range(configuration.inputs) {
        if strings.HasPrefix(itype, "tcp:") {
            go launchTcpServer(input.parameters["hostname"].(string), input.parameters["port"].(int))
        } else if strings.HasPrefix(itype, "udp:") {
            go launchUdpServer(input.parameters["hostname"].(string), input.parameters["port"].(int))
        }
    }

    // We block to avoid to quit the system
    timer := time.NewTimer(time.Second)
    go func() {
        <-timer.C
        log.Println("golog is waiting for incoming events")
    }()
    <-done
    log.Println("Byebye")
}

