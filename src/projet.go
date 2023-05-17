package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const idSize = 4
const typeSize = 1
const lengthSize = 2
const userlengthSize = 1
const flagSize = 4
const hashSize = 32
const messageMaxSize = 1064
const IPv4Size = 6
const IPv6Size = 18
const dateSize = 32
const inReplyToSize = 32


const helloType = 0
const helloreplyType = 128
const rootType = 129
const errorType = 254
const getdatumType = 2
const datumType = 130
const nodatumType = 131
const natclientType = 132
const natserverType = 133
const rootrequestType = 1

const servername = "https://jch.irif.fr"
const serverport = 8443

// obtenir l'adresse du serveur
const getservaddr = "/udp-address/"

// // s'enregister au près du serveur
const postregister = "/register/"

//obtenir la liste des pairs
const getpeers = "/peers/"

//durée au bout de laquelle un pair/le serveur nous oublie
const timeoutduration = 55

//nombre maximum de connexions
const maxconnection = 1024

//RTT de base en millisecondes
const RTTms = 2000

// objet JSON enregistrement auprès du serveur
type jsonRegister struct {
	Name string `json:"name"`
	Key  []byte `json:"key,omitempty"`
}

type Adresse struct {
	Ip   string `json:"ip"`
	Port int    `json:"port"`
}

// objet JSON addresses de pairs
type jsonAddr struct {
	Name      string     `json:"name"`
	Addresses *[]Adresse `json:"addresses"`
	//Key       []byte     `json:"key,omitempty"`
}

//Structure d'un paquet de base
type TLV struct {
	Id        [idSize]byte
	Type      byte
	Length    [lengthSize]byte
	Body      []byte
	Signature []byte
}

//Structure d'un paquet de type Hello ou HelloReply
type Hello struct {
	Id             [idSize]byte
	Type           byte
	Length         [lengthSize]byte
	Flags          [flagSize]byte
	UsernameLength byte
	Username       []byte
	Signature      []byte
}

type Datum struct {
	Id     [idSize]byte
	Type   byte
	Length [lengthSize]byte
	Hash   []byte
	Value  []byte
}

type Message struct {
	Type 		byte
	Date 		[dateSize]byte
	InReplyTo	[inReplyToSize]byte
	Length 		[lengthSize]byte 
	Body 		[]byte
}


type NatTrv struct {
	Id            [idSize]byte
	Type          byte
	Length        [lengthSize]byte
	RemoteAddress []byte
}

func RTT(start time.Time) time.Duration {
	return time.Since(start)
}

func getID(mes *TLV) []byte {
	return mes.Id[:]
}

func isHello(mes *TLV) bool {
	fmt.Println(mes)
	return mes.Type == helloType
}

func isHelloReply(mes *TLV) bool {
	return mes.Type == helloreplyType
}

func isGetDatum(mes *TLV) bool {
	return mes.Type == getdatumType
}

func isGetRoot(mes *TLV) bool {
	return mes.Type == rootType
}

func isErrorMessage(mes *TLV) bool {
	return mes.Type == errorType
}

func isNatTrv(mes *TLV) bool {
	return mes.Type == natserverType
}

func isDatum(mes *TLV) bool {
	return mes.Type == datumType
}

func isNoDatum(mes *TLV) bool {
	return mes.Type == nodatumType
}

func toByte(mes *Hello) []byte {
	//obtention du champs Length
	len := binary.BigEndian.Uint16(mes.Length[:])
	buf := make([]byte, idSize+typeSize+lengthSize+len)
	copy(buf[:idSize], mes.Id[:])
	buf[idSize] = mes.Type
	copy(buf[idSize+typeSize:idSize+typeSize+lengthSize], mes.Length[:])
	if len >= flagSize+userlengthSize {
		copy(buf[idSize+typeSize+lengthSize:idSize+typeSize+lengthSize+flagSize], mes.Flags[:])
		buf[idSize+typeSize+lengthSize+flagSize] = mes.UsernameLength
		if mes.Username[:] != nil {
			copy(buf[idSize+typeSize+lengthSize+flagSize+userlengthSize:], mes.Username[:])
		}
	}
	//TODO
	//handle signatures
	return buf
}

func tlvToByte(mes *TLV) []byte {
	len := binary.BigEndian.Uint16(mes.Length[:])
	buf := make([]byte, idSize+typeSize+lengthSize+len)
	copy(buf[:idSize], mes.Id[:])
	buf[idSize] = mes.Type
	copy(buf[idSize+typeSize:idSize+typeSize+lengthSize], mes.Length[:])
	copy(buf[idSize+typeSize+lengthSize:], mes.Body[:])
	return buf
}

func tlvToHello(mes *TLV) *Hello {
	var h Hello
	len := binary.BigEndian.Uint16(mes.Length[:])
	copy(h.Id[:], mes.Id[:])
	h.Type = mes.Type
	copy(h.Length[:], mes.Length[:])
	if mes.Body != nil {
		copy(h.Flags[:], mes.Body[:flagSize])
		h.UsernameLength = mes.Body[flagSize]
		h.Username = make([]byte, len-(flagSize+userlengthSize))
		copy(h.Username[:], mes.Body[flagSize+userlengthSize:])
	}
	return &h
}

func datumToByte(mes *Datum) []byte {
	len := binary.BigEndian.Uint16(mes.Length[:])
	fmt.Printf("Value of length obtained: %d\n", len)
	buf := make([]byte, idSize+typeSize+lengthSize+len)
	fmt.Println("Buffer created")
	fmt.Printf("\t%s\n", buf)
	copy(buf[:idSize], mes.Id[:])
	fmt.Println("ID copied")
	fmt.Printf("\t%s\n", buf)
	buf[idSize] = mes.Type
	fmt.Println("Type copied")
	fmt.Printf("\t%s\n", buf)
	copy(buf[idSize+typeSize:idSize+typeSize+lengthSize], mes.Length[:])
	fmt.Println("Length copied")
	fmt.Printf("\t%s\n", buf)
	copy(buf[idSize+typeSize+lengthSize:idSize+typeSize+lengthSize+hashSize], mes.Hash[:])
	fmt.Println("Hash copied")
	fmt.Printf("\t%s\n", buf)
	if mes.Value != nil {
		//il existe une Value
		copy(buf[idSize+typeSize+lengthSize+hashSize:], mes.Value[:])
		fmt.Println("Value copied")
		fmt.Printf("\t%s\n", buf)
	}
	fmt.Printf("\t%s\n", buf)
	return buf
}

func readDatum(mes *Datum,h []byte) []byte{
	hash := mes.Hash
	if bytes.Compare(h,hash)== 0{
		message := mes.Value
		return message
	}
	return nil
}

/*func readTypeDatum(mes []byte) int {
	return mes[0]
}*/

func afficherMessage(conn *net.UDPConn,paquet []byte, len uint16,id uint32,addr *net.UDPAddr) {
	pos:=40
	p:=0
	var mes *TLV
	//var paddr *net.UDPAddr
	if paquet[39]==1{
		fmt.Println("Internal")
		for i:=len-1;i>32;i=i-32{
			fmt.Println("hash n° ",p)
			fmt.Println(paquet[pos:pos+32])
			h :=paquet[pos:pos+32]

			message3:= makeGetDatum(id,h)
			askDatum(conn,addr,message3)
			mes, _ = recvFromTLV(conn)
			if mes==nil {
				return
			}
			fmt.Println("requête reçue")
			//handlePacket(mes, conn, paddr, identity, id)
			rep4 := tlvToByte(mes)
			len2 := binary.BigEndian.Uint16(rep4[5:7]) - 32
			if rep4[39]==0{
				fmt.Println(rep4[76:78])
				len3 := binary.BigEndian.Uint16(rep4[76:78])
				fmt.Println(len3)
				fmt.Println(string(rep4[78:(78+len3)]))
			}
			if rep4[39]==1{
				afficherMessage(conn,rep4,len2,id,addr)
			}
			pos =pos+32
			p++
		}
	}
}


func toHello(buf []byte) *Hello {
	var mes Hello
	//ID
	copy(mes.Id[:], buf[:idSize])

	//Type
	tmp := buf[idSize : idSize+typeSize]
	mes.Type = tmp[0]

	//Length
	copy(mes.Length[:], buf[idSize+typeSize:idSize+typeSize+lengthSize])

	//Flags
	copy(mes.Flags[:], buf[idSize+typeSize+lengthSize:idSize+typeSize+lengthSize+flagSize])

	//UsernameLength
	tmp = buf[idSize+typeSize+lengthSize+flagSize : idSize+typeSize+lengthSize+flagSize+userlengthSize]
	mes.UsernameLength = tmp[0]

	//Username
	n := uint8(mes.UsernameLength)
	mes.Username = make([]byte, n)
	copy(mes.Username[:], buf[idSize+typeSize+lengthSize+flagSize+lengthSize:idSize+typeSize+lengthSize+flagSize+lengthSize+n])
	//TODO
	//handle signatures
	return &mes
}

func helloToTLV(h *Hello) *TLV {
	var mes TLV

	//ID
	copy(mes.Id[:], h.Id[:])

	//Type
	mes.Type = h.Type

	//Length
	copy(mes.Length[:], h.Length[:])

	//Body
	len := binary.BigEndian.Uint16(mes.Length[:])
	mes.Body = make([]byte, len)

	copy(mes.Body[:flagSize], h.Flags[:])
	mes.Body[flagSize] = h.UsernameLength
	copy(mes.Body[flagSize+userlengthSize:], h.Username)
	return &mes
}

//TODEL
//Doublon avec la fonction tlvToHello
func messageToHello(mes *TLV) *Hello {
	var h Hello

	//ID
	//fmt.Println("Copie de ID")
	copy(h.Id[:], mes.Id[:])

	//Type
	//fmt.Println("Copie de Type")
	h.Type = mes.Type

	//Length
	//fmt.Println("Copie de Length")
	copy(h.Length[:], mes.Length[:])

	//Flag
	//fmt.Println("Copie de Flag")
	copy(h.Flags[:], mes.Body[:flagSize])

	//UsernameLength
	//fmt.Println("Copie de UsernameLength")
	tmp := mes.Body[flagSize : flagSize+userlengthSize]
	h.UsernameLength = tmp[0]

	//Username
	//fmt.Println("Création de Username")
	h.Username = make([]byte, h.UsernameLength)
	//fmt.Println("Copie de Username")
	copy(h.Username[:], mes.Body[flagSize+userlengthSize:])
	return &h
}

func toTLV(buf []byte) *TLV {
	var mes TLV
	//ID
	copy(mes.Id[:], buf[:idSize])

	//Type
	tmp := buf[idSize : idSize+typeSize]
	mes.Type = tmp[0]

	//Length
	copy(mes.Length[:], buf[idSize+typeSize:idSize+typeSize+lengthSize])

	//Body
	n := binary.BigEndian.Uint16(mes.Length[:])
	mes.Body = make([]byte, n)
	copy(mes.Body[:], buf[idSize+typeSize+lengthSize:idSize+typeSize+lengthSize+n])
	return &mes
}

func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ":")
  }

func toUDPAddress(addr *Adresse) *net.UDPAddr {
	if IsIPv6(addr.Ip) {
		udpaddr, err := net.ResolveUDPAddr("udp6","["+addr.Ip+"]:"+strconv.Itoa(addr.Port))
		if err != nil {
			log.Fatal(err)
		}
		return udpaddr
	}
		
	udpaddr, err := net.ResolveUDPAddr("udp", addr.Ip+":"+strconv.Itoa(addr.Port))
	if err != nil {
		log.Fatal(err)
	}
	
	return udpaddr
}

func toUDP6Address(addr *Adresse) *net.UDPAddr {
	udpaddr, err := net.ResolveUDPAddr("udp6", addr.Ip+":"+strconv.Itoa(addr.Port))
	if err != nil {
		log.Fatal(err)
	}
	return udpaddr
}

func listen() *net.UDPConn {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Fatal(err)
	}
	return conn
	//dans main:
	//defer conn.Close()
}

func listenV6() *net.UDPConn {
	conn, err := net.ListenUDP("udp6", nil)
	if err != nil {
		log.Fatal(err)
	}
	return conn
	//dans main:
	//defer conn.Close()
}

func makeHello(login *jsonRegister, id uint32) *Hello {
	var req Hello
	//création de l'ID
	binary.BigEndian.PutUint32(req.Id[:], id)

	//Type
	req.Type = uint8(helloType)

	//taille du nom de pair
	n := uint8(len(login.Name))
	req.UsernameLength = n

	//copie du nom de pair
	req.Username = make([]byte, n)
	copy(req.Username, []byte(login.Name))

	//taille du corps
	//on additionne la taille des champs
	//Flags, UsernameLength et Username
	//TODO
	//ajouter la taille de la signature
	m := uint16(flagSize + userlengthSize + n)
	binary.BigEndian.PutUint16(req.Length[:], m)

	//Flags
	for i := range req.Flags {
		req.Flags[i] = 0
	}

	//TODO
	//gestion des signatures
	return &req
}

func makeHelloReply(identity *jsonRegister, Id []byte) *Hello {
	var res Hello
	//Copie de l'ID
	copy(res.Id[:], Id[:])

	//Type
	res.Type = uint8(helloreplyType)

	//taille du corps
	n := len(identity.Name)
	binary.BigEndian.PutUint16(res.Length[:], uint16(idSize+userlengthSize+n))

	//Flags
	for i := 0; i < flagSize; i++ {
		res.Flags[i] = 0
	}

	//UsernameLength
	res.UsernameLength = byte(n)

	//Username
	res.Username = make([]byte, n)
	copy(res.Username, []byte(identity.Name))
	//TODO
	//gestion des signatures
	return &res
}

func makeErrorTLV(message string, identity *jsonRegister, id uint32) *TLV {
	var res TLV
	//création de l'ID
	binary.BigEndian.PutUint32(res.Id[:], id)

	//Type
	res.Type = errorType

	//taille du message d'erreur
	n := uint16(len(message))

	//taille du corps
	binary.BigEndian.PutUint16(res.Length[:], n)

	//copie du corps du message
	res.Body = make([]byte, n)
	copy(res.Body, []byte(message))

	return &res
}

func askRoot(conn *net.UDPConn, addr *net.UDPAddr, req *TLV) int {
	buf := tlvToByte(req)

	//envoie du Hello
	n, err := conn.WriteToUDP(buf, addr)
	if err != nil {
		log.Fatal(err)
	}
	return n
}

func askDatum(conn *net.UDPConn, addr *net.UDPAddr, req *Datum) int {
	buf := datumToByte(req)

	//envoie du Hello
	n, err := conn.WriteToUDP(buf, addr)
	if err != nil {
		log.Fatal(err)
	}
	return n
}


func sendToHello(conn *net.UDPConn, addr *net.UDPAddr, req *Hello) int {
	//encodage de la requête en []byte
	buf := toByte(req)

	//envoie du Hello
	n, err := conn.WriteToUDP(buf, addr)
	if err != nil {
		log.Fatal(err)
	}
	return n
}

func recvFrom(conn *net.UDPConn) ([]byte, *net.UDPAddr) {
	//création d'un tampon
	//de la taille maximum d'un paquet UDP
	buf := make([]byte, messageMaxSize)

	//Lecture d'une entrée
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		log.Fatal(err)
	}

	return buf[:n], addr
}

func recvFromHello(conn *net.UDPConn) (*Hello, *net.UDPAddr) {
	//création d'un tampon
	//de la taille maximum d'un paquet UDP
	buf := make([]byte, messageMaxSize)

	//Lecture d'une entrée
	_, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		log.Fatal(err)
	}

	//décodage en message
	res := toHello(buf)
	return res, addr
}

func recvFromTLV(conn *net.UDPConn) (*TLV, *net.UDPAddr) {
	//création d'un tampon
	//de la taille maximum d'un paquet UDP
	buf := make([]byte, messageMaxSize)

	//Lecture d'une entrée
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))	
	_, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		/*if os.IsTimeout(err){
			for ok := true; ok; ok= (err != nil) {

		log.Fatal(err)*/
		return nil,nil
	}

	//décodage en message
	res := toTLV(buf)
	if res.Type == errorType {
		fmt.Println("TLV d'erreur reçu:")
		fmt.Printf("%s\n", res.Body)
	}
	return res, addr
}

func makeNoDatum(dat *Datum, id uint32) *Datum {
	var nodat Datum
	//ID
	binary.BigEndian.PutUint32(nodat.Id[:], id)

	//Type
	nodat.Type = nodatumType

	//Length
	binary.BigEndian.PutUint16(nodat.Length[:], hashSize)

	//Hash
	copy(nodat.Hash[:], dat.Hash[:])
	return &nodat
}

func messageToDatum(mes *TLV) *Datum {
	var dat Datum
	//ID
	copy(dat.Id[:], mes.Id[:])

	//Type
	dat.Type = mes.Type

	//Length
	copy(dat.Length[:], mes.Length[:])

	//Hash
	copy(dat.Hash[:], mes.Body[:hashSize])

	//Value
	n := binary.BigEndian.Uint16(mes.Length[:])
	if n > hashSize {
		//il existe une Value
		dat.Value = make([]byte, n-hashSize)
		copy(dat.Value[:], mes.Body[hashSize:])
	}

	return &dat
}

func sendToDatum(conn *net.UDPConn, addr *net.UDPAddr, req *Datum) int {
	//encodage de la requête en []byte
	buf := datumToByte(req)

	//envoie du Hello
	n, err := conn.WriteToUDP(buf, addr)
	if err != nil {
		log.Fatal(err)
	}
	return n
}

//TOFIX
func makeGetDatum(id uint32, hash []byte) *Datum {
	var dat Datum
	//ID
	binary.BigEndian.PutUint32(dat.Id[:], id)

	//Type
	dat.Type = getdatumType

	//Length
	binary.BigEndian.PutUint16(dat.Length[:], hashSize)
	//TODO

	dat.Hash = hash
	//comprendre quoi mettre dans Value
	return &dat
}

func makeRootRequest(id uint32) *TLV {
	var rreq TLV
	//ID
	binary.BigEndian.PutUint32(rreq.Id[:], id)

	//Type
	rreq.Type = rootrequestType

	//Length
	binary.BigEndian.PutUint16(rreq.Length[:], 0)
	return &rreq
}

func sendTo(conn *net.UDPConn, addr *net.UDPAddr, buf []byte) int {
	n, err := conn.WriteToUDP(buf, addr)
	if err != nil {
		log.Fatal(err)
	}
	return n
}

func getAddr() *[]Adresse {
	host := "https://jch.irif.fr:8443/udp-address"
	var r []Adresse

	resp, err := http.Get(host)
	if err != nil {
		fmt.Println("erreur lors de la connexion :", err)
		return nil
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("erreur de lecture :", err)
		return nil
	}

	err = json.Unmarshal(body, &r)
	if err != nil {
		fmt.Println("erreur de unmarshal :", err)
		return nil
	}
	return &r
}

// fonction permettant de s'enregistrer auprès du server
func register(data []byte) {
	host := "https://jch.irif.fr:8443/register"
	/*data,err := json.Marshal(id)
	if err != nil {
		fmt.Println("erreur marshal",err)
		return
	}*/

	resp, err := http.Post(host, "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("erreur post", err)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("erreur réponse post", err)
		return
	}
	fmt.Println(string(body))

}

// renvoi la liste des noms de pairs enregistrés
func getListPeer() string {
	host := "https://jch.irif.fr:8443/peers"
	resp, err := http.Get(host)
	if err != nil {
		fmt.Println("erreur lors de la connexion :", err)
		return ""
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("erreur de lecture :", err)
		return ""
	}
	print(string(body))
	return string(body)

}

// renvoi la/les addresse(s) du pair "nom"
func getPeerAdress(nom string) *jsonAddr {
	host := "https://jch.irif.fr:8443/peers/" + nom
	var r *jsonAddr

	resp, err := http.Get(host)
	if err != nil {
		fmt.Println("erreur lors de la connexion :", err)
		return nil
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("erreur de lecture :", err)
		return nil
	}

	//fmt.Println(string(body))

	err = json.Unmarshal(body, &r)
	if err != nil {
		fmt.Println("erreur de unmarshal getPeerAdress:", err)
		return nil
	}
	//fmt.Println(r)
	//fmt.Println(r.Addresses)
	return r

}

// génère la clé privée, appelé lors de la génération de la clé publique
func generate_private() *ecdsa.PrivateKey {
	privateKey, err :=
		ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("erreur génération de clé privée :", err)
		return nil
	}
	return privateKey
}

// génère la clé publique
func generate_public() *ecdsa.PublicKey {
	privateKey := generate_private()
	publicKey, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("erreur génération de clé public")
		return nil
	}
	return publicKey
}

// formate la clé publique en suite de 64 bytes
func formate_key(publicKey *ecdsa.PublicKey) []byte {
	formatted := make([]byte, 64)
	publicKey.X.FillBytes(formatted[:32])
	publicKey.Y.FillBytes(formatted[32:])
	return formatted
}

func parse_key(data []byte) ecdsa.PublicKey {
	var x, y big.Int
	x.SetBytes(data[:32])
	y.SetBytes(data[32:])
	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}
	return publicKey
}

func signature_message(data []byte, privateKey *ecdsa.PrivateKey) []byte {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		fmt.Println("erreur de signature", err)
		return []byte{}
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature
}

func verif_message(data []byte, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) bool {
	var r, s big.Int
	signature := signature_message(data, privateKey)
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	hashed := sha256.Sum256(data)
	ok := ecdsa.Verify(publicKey, hashed[:], &r, &s)
	return ok
}

func testAPIRest() {
	fmt.Println("******récupération de l'adresse du serveur:*******")
	addresses := getAddr()
	fmt.Printf("%+v\n", addresses)
	fmt.Println("*****enregistrement auprès du serveur*****")
	time.Sleep(2 * time.Second)
	identity := &jsonRegister{Name: "Aut", Key: []byte{}}
	data, err := json.Marshal(identity)
	if err != nil {
		fmt.Println("erreur marshal", err)
		return
	}
	fmt.Println(string(data))
	fmt.Println(len(identity.Name))
	var test *jsonRegister
	err = json.Unmarshal(data, &test)
	if err != nil {
		fmt.Println("erreur de unmarshal :", err)

	}
	fmt.Println(len(test.Key))
	register(data)

	fmt.Println("******récupération de la liste des pairs*****")
	time.Sleep(2 * time.Second)
	nom := getListPeer()
	listPeer := strings.Split(nom, "\n")
	time.Sleep(2 * time.Second)
	fmt.Println(listPeer)
	fmt.Println(len(listPeer))
	time.Sleep(2 * time.Second)
	fmt.Println("*****affichage des adresses des pairs*****")
	n := len(listPeer)
	for i := 0; i < n-1; i++ {
		fmt.Println("********pair:" + listPeer[i] + "********")
		p := getPeerAdress(listPeer[i]).Addresses
		fmt.Println(p)
		time.Sleep(2 * time.Second)
	}
}

func testEncDecHello(identity *jsonRegister, id uint32) {
	//test makeHello
	//création de l'ID
	mrand.Seed(time.Now().Unix())
	req := makeHello(identity, id)
	fmt.Printf("%+v\n", req)
	buf := toByte(req)
	fmt.Println(buf)
	res := toHello(buf)
	fmt.Printf("%+v\n", res)
}

func testHelloHelloReply(identity *jsonRegister, id uint32) {
	//récupération de l'adresse du serveur
	serv := getAddr()

	//enregistrement auprès du serveur
	bufid, err := json.Marshal(identity)
	if err != nil {
		log.Fatal(err)
	}
	register(bufid)

	//création de socket UDP
	addr := toUDPAddress(&(*serv)[0])
	fmt.Println("adresse du pair ciblé")
	conn := listen()
	defer conn.Close()

	//création de la requête
	req := makeHello(identity, id)
	fmt.Printf("Requête à envoyer: %+v\n", req)

	//envoie de la requête
	sendToHello(conn, addr, req)

	//réception de la réponse
	res, paddr := recvFromTLV(conn)
	fmt.Printf("Requête reçu: %+v\n", res)
	fmt.Printf("Addresse du pair obtenue: %s\n", paddr.String())
}

func testHelloHelloReplyHello(identity *jsonRegister, id uint32) {
	//récupération de l'adresse du serveur
	serv := getAddr()

	//enregistrement auprès du serveur
	bufid, err := json.Marshal(identity)
	if err != nil {
		log.Fatal(err)
	}
	register(bufid)

	//création de socket UDP
	addr := toUDPAddress(&(*serv)[0])
	fmt.Println("adresse du pair ciblé")
	conn := listen()
	defer conn.Close()

	//création de la requête
	req := makeHello(identity, id)
	fmt.Printf("Requête à envoyer: %+v\n", req)

	//envoie de la requête
	sendToHello(conn, addr, req)

	//réception de la réponse
	res, paddr := recvFromTLV(conn)
	fmt.Printf("Requête reçu: %+v\n", res)
	fmt.Printf("Addresse du pair obtenue: %s\n", paddr.String())

	//réception d'un Hello
	res, paddr = recvFromTLV(conn)
	fmt.Printf("Requête reçu: %+v\n", res)
	fmt.Printf("Addresse du pair obtenue: %s\n", paddr.String())

	//création de la réponse
	req = messageToHello(res)
	req = makeHelloReply(identity, req.Id[:])
	fmt.Printf("Requête à envoyer: %+v\n", req)

	//envoie de la réponse
	sendToHello(conn, paddr, req)
}

func testToHello(identity *jsonRegister, id uint32) {
	h := makeHello(identity, id)
	fmt.Printf("Hello: %+v\n", h)
	mes := helloToTLV(h)
	fmt.Printf("TLV du hello: %+v\n", mes)
	h = messageToHello(mes)
	fmt.Printf("Hello du message du hello: %+v\n", h)
}

func handlePacket(mes *TLV, conn *net.UDPConn, addr *net.UDPAddr, identity *jsonRegister, id uint32) int {
	fmt.Printf("\thandle: Depuis l'adresse: %s\n", conn.LocalAddr().String())
	if isHello(mes) {
		fmt.Printf("\thandle: Requête Hello reçu: %+v\n", mes)
		res := makeHelloReply(identity, mes.Id[:])
		fmt.Printf("\thandle: HelloReply encodé: %+v\n", res)
		fmt.Println("Préparation de l'envoie d'une requête")
		sendToHello(conn, addr, res)
		return helloType
	} else if isHelloReply(mes) {
		fmt.Printf("\thandle: Requête HelloReply reçu: %+v\n", mes)
		res := messageToHello(mes)
		fmt.Printf("%s\n", res.Username)
		return helloreplyType
	} else if isGetDatum(mes) {
		fmt.Printf("\thandle: Requête GetDatum reçu: %+v\n", mes)
		fmt.Printf("\thandle: depuis l'adresse: %s\n", conn.LocalAddr().String())
		dat := messageToDatum(mes)
		fmt.Printf("\thandle: Message encodé: %+v\n", dat)
		nodat := makeNoDatum(dat, id)
		sendToDatum(conn, addr, nodat)
		return getdatumType
	} else if isNatTrv(mes) {
		fmt.Printf("\thandle: Requête Nat Traversal Server reçu reçu: %+v\n", mes)
		//TODO
		//récupérer l'addresse dans le champ RemoteAddress
		//la passer dans la fonction toUDPAddress()
		//faire un sendtoHello à cette adresse
		return natserverType
	} else if isErrorMessage(mes) {
		fmt.Printf("\thandle: Message d'erreur reçu: %+v\n", mes)
		fmt.Printf("\thandle: Erreur: %s\n", mes.Body)
		return errorType
	} else {
		res := makeErrorTLV("Type de paquet inconnu", identity, id)
		fmt.Printf("\thandle: Message d'erreur préparé à l'envoie: %+v\n", res)
		buf := tlvToByte(res)
		sendTo(conn, addr, buf)
		return int(mes.Type)
	}
}

func handlePacketRTT(mes *TLV, conn *net.UDPConn, addr *net.UDPAddr, identity *jsonRegister, id uint32) int {
	fmt.Printf("\thandle: Depuis l'adresse: %s\n", conn.LocalAddr().String())
	if isHello(mes) {
		fmt.Printf("\thandle: Requête Hello reçu: %+v\n", mes)
		res := makeHelloReply(identity, mes.Id[:])
		fmt.Printf("\thandle: HelloReply encodé: %+v\n", res)
		fmt.Println("Préparation de l'envoie d'une requête")
		sendToHello(conn, addr, res)
		return helloType
	} else if isHelloReply(mes) {
		fmt.Printf("\thandle: Requête HelloReply reçu: %+v\n", mes)
		res := messageToHello(mes)
		fmt.Printf("%s\n", res.Username)
		return helloreplyType
	} else if isGetDatum(mes) {
		fmt.Printf("\thandle: Requête GetDatum reçu: %+v\n", mes)
		fmt.Printf("\thandle: depuis l'adresse: %s\n", conn.LocalAddr().String())
		dat := messageToDatum(mes)
		fmt.Printf("\thandle: Message encodé: %+v\n", dat)
		nodat := makeNoDatum(dat, id)
		sendToDatum(conn, addr, nodat)
		return getdatumType
	} else if isNatTrv(mes) {
		fmt.Printf("\thandle: Requête Nat Traversal Server reçu reçu: %+v\n", mes)
		//TODO
		//récupérer l'addresse dans le champ RemoteAddress
		//la passer dans la fonction toUDPAddress()
		//faire un sendtoHello à cette adresse
		return natserverType
	} else if isErrorMessage(mes) {
		fmt.Printf("\thandle: Message d'erreur reçu: %+v\n", mes)
		fmt.Printf("\thandle: Erreur: %s\n", mes.Body)
		return errorType
	} else if isGetRoot(mes){
		fmt.Printf("\thandle: Requête Racine reçu: %+v\n", mes)
		return rootType
	
	} else if isDatum(mes){
		fmt.Printf("\thandle: Message reçu: %+v\n", mes)
		return datumType
	
	} else if isNoDatum(mes){
		fmt.Printf("\thandle: NoDatum reçu: %+v\n", mes)
		return nodatumType
	
	} else {
		res := makeErrorTLV("Type de paquet inconnu", identity, id)
		fmt.Printf("\thandle: Message d'erreur préparé à l'envoie: %+v\n", res)
		buf := tlvToByte(res)
		sendTo(conn, addr, buf)
		return int(mes.Type)
	}
}

func handleSession(pconn *net.UDPConn, mes *TLV, paddr *net.UDPAddr, identity *jsonRegister, id uint32, end chan *net.UDPAddr) {
	//TODO
	//créer un timer
	timer := time.NewTimer(timeoutduration * time.Minute)

	var mes1 *TLV
	mes1 = mes
	//gérer la réponse
	for {
		select {
		case <-timer.C:
			end <- paddr
			return
		default:
			tp := handlePacket(mes1, pconn, paddr, identity, id)
			if tp == helloType {
				timer.Reset(timeoutduration * time.Minute)
			}
			mes1, paddr = recvFromTLV(pconn)
		}
	}
}

func sessionPeer(identity *jsonRegister, id uint32, name string) {
	//récupération de l'adresse du pair
	peer := getPeerAdress(name)
    //fmt.Println(peer)
	//création de socket UDP
	tmp := peer.Addresses
	addr := toUDPAddress(&(*tmp)[0])
	var conn *net.UDPConn
	a := (*tmp)[0]
	//fmt.Printf("addresse obtenue %+v\n", addr)
	if IsIPv6((a.Ip)) {
		conn = listenV6()
	} else {
		conn = listen()
	}
	defer conn.Close()

	req := makeHello(identity, id)
	//fmt.Printf("requête %+v\n", req)
	sendToHello(conn, addr, req)
	fmt.Println("requête envoyée")
	var mes *TLV
	var paddr *net.UDPAddr
	for {
		mes, paddr = recvFromTLV(conn)
		if mes==nil {
			return
		}
		fmt.Println("requête reçue")
		handlePacket(mes, conn, paddr, identity, id)
		if isHelloReply(mes) {
			tmp := tlvToHello(mes)
			fmt.Printf("Session établie avec le pair: %s\n", tmp.Username)
			req2 := makeRootRequest(id)
			//return
			askRoot(conn, addr, req2)
			
		}
		if isGetRoot(mes) {
			fmt.Println("racine recue")
			req3:=makeGetDatum(id,mes.Body)
			askDatum(conn,addr,req3)
			//return
		}
		if isDatum(mes){
			len := binary.BigEndian.Uint16(mes.Length[:]) -32
			afficherMessage(conn,tlvToByte(mes),len,id,addr)
			return
			
		}


	}
	
}

func sessionServ(conn *net.UDPConn, identity *jsonRegister, id uint32) {
	//récupération de l'adresse du serveur
	serv := getAddr()

	//enregistrement auprès du serveur
	bufid, err := json.Marshal(identity)
	if err != nil {
		log.Fatal(err)
	}
	register(bufid)

	//création de socket UDP
	var addr *net.UDPAddr
	for _, value := range *serv {
		str := value.Ip
		fmt.Printf("Adresse %s\n", str)
		ip := net.ParseIP(str)
		if ip.To4() != nil {
			fmt.Println("Adresse valide")
			addr = &net.UDPAddr{IP: ip, Port: value.Port}
			break
		}
	}
	if addr == nil {
		log.Fatal("Aucune adresse valide obtenue")
	}
	fmt.Printf("addresse obtenue %+v\n", addr)

	req := makeHello(identity, id)
	sendToHello(conn, addr, req)
	start := time.Now()
	rtt := RTTms * time.Millisecond
	var mes *TLV
	var paddr *net.UDPAddr
	for {
		if isRegistered(identity.Name) {
			println("Enregistré sur le serveur!")
			break
		}
		mes, paddr = recvFromTLV(conn)
		rtt = RTT(start)
		fmt.Printf("RTT: %s", rtt)
		handlePacket(mes, conn, paddr, identity, id)
	}
	for {
		time.Sleep(timeoutduration * time.Minute)
		fmt.Printf("Hello sent at %s\n", time.Now())
		sendToHello(conn, addr, req)
		//TODO
		//wait for helloReply
		//handle packet loss
		//	reinit start
		//	calculate difference
		//	apply RTO formula
	}
}

func sessionServV6(conn *net.UDPConn, identity *jsonRegister, id uint32) {
	serv := getAddr()
	fmt.Printf("%+v\n", serv)

	//enregistrement auprès du serveur
	bufid, err := json.Marshal(identity)
	if err != nil {
		log.Fatal(err)
	}
	register(bufid)
	fmt.Println("/register/ envoyé")
	var addr *net.UDPAddr
	for _, value := range *serv {
		str := value.Ip
		fmt.Printf("Adresse: %s\n", str)
		ip := net.ParseIP(str)
		if ip.To4() == nil && ip.To16() != nil {
			fmt.Println("Adresse IPV6 valide")
			addr = &net.UDPAddr{IP: ip, Port: value.Port}
			break
		}
	}
	req := makeHello(identity, id)
	fmt.Printf("requête: %+v\n", req)
	sendToHello(conn, addr, req)
	fmt.Printf("requête envoyée à l'adresse %+v\n", addr)
	fmt.Printf("via la socket %+v\n", conn.LocalAddr())
	start := time.Now()
	var mes *TLV
	var paddr *net.UDPAddr
	for {
		if isRegistered(identity.Name) {
			println("Enregistré sur le serveur!")
			break
		}
		mes, paddr = recvFromTLV(conn)
		rtt := RTT(start)
		fmt.Printf("RTT: %s", rtt)
		handlePacket(mes, conn, paddr, identity, id)
	}
	for {
		time.Sleep(timeoutduration * time.Minute)
		fmt.Printf("Hello sent at %s\n", time.Now())
		sendToHello(conn, addr, req)
		//TODO
		//wait for helloReply
		//handle packet loss
		//	reinit start
		//	calculate difference
		//	apply RTO formula
	}
}

func testRootTransfer(identity *jsonRegister, id uint32, name string) {
	//enregistrement auprès du serveur
	bufid, err := json.Marshal(identity)
	if err != nil {
		log.Fatal(err)
	}
	register(bufid)

	peer := getPeerAdress(name)
	fmt.Println("Adresse Obtenue")
	fmt.Printf("\t%+v\n", peer)

	//création de socket UDP
	tmp := (*peer.Addresses)[0]
	addr := toUDPAddress(&tmp)
	conn := listen()
	defer conn.Close()

	rreq := makeRootRequest(id)
	fmt.Printf("Requête Root Requet créée: %+v\n", rreq)
	req := tlvToByte(rreq)
	fmt.Println("Tableau de byte correspondant: ", req)
	sendTo(conn, addr, req)
	res, paddr := recvFrom(conn)
	fmt.Println("Réponse reçue: ", res)
	fmt.Printf("Depuis l'adresse: %+v\n", paddr)
	rreq = toTLV(res)
	fmt.Println("Réponse encodée: ", rreq)
	fmt.Printf("%s\n", rreq.Body[:])
}

func isRegistered(name string) bool {
	res, _ := http.Get(servername + ":" + strconv.Itoa(serverport) + getpeers + name)
	if res.StatusCode == 404 {
		return false
	}
	return true
}

func serv(conn *net.UDPConn, tlvs chan *TLV, addrs chan *net.UDPAddr) {
	for {
		mes, paddr := recvFromTLV(conn)
		tlvs <- mes
		addrs <- paddr
	}
}

//
//Code copié-collé depuis stack-overflow
var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}
	return string(b)
}

//

func main() {
	mrand.Seed(time.Now().UnixNano())
	str := randStringRunes(10)
	identity := jsonRegister{Name: str, Key: []byte{}}
	var id uint32 = mrand.Uint32()
	fmt.Println("Mon Id est", id)
	fmt.Println("Mon nom est", str)
	conn := listen()
	defer conn.Close()
	fmt.Printf("Adresse de socket %+v\n", conn.LocalAddr())
	go sessionServ(conn, &identity, id)
	//TLV reçus
	//tlvs := make(chan *TLV)
	//destinateurs des TLVs reçus
	//addrs := make(chan *net.UDPAddr, maxconnection)
	//pairs connus
	//knownaddr := make(map[string]bool)
	//pairs à supprimer de notre liste
	//end := make(chan *net.UDPAddr)

	lst := getListPeer()
	listPeer := strings.Split(lst, "\n")
	fmt.Println(lst)
	for i:=0;i<(len(listPeer)-1);i++ {
		go sessionPeer(&identity,id,listPeer[i])
	}

	for {
		fmt.Println("J'attends...")
		buf := make([]byte, messageMaxSize)

		//Lecture d'une entrée
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))	
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			/*if os.IsTimeout(err){
				for ok := true; ok; ok= (err != nil) {

			log.Fatal(err)*/
			continue
		}
		fmt.Println(n)
		fmt.Println(buf)
		///décodage en message
		/*mes := toTLV(buf[:n])
		if mes.Type == errorType {
			fmt.Println("TLV d'erreur reçu:")
			fmt.Printf("%s\n", mes.Body)
		}*/
		//TODO
		//NE REÇOIT RIEN!!!
		//IMPOSSIBLE DE CONTACTER MON SERVEUR
		/*serv(conn, tlvs, addrs)
		mes := <-tlvs
		paddr := <-addrs
		fmt.Printf("Message reçu: %+v\n", mes)
		fmt.Printf("depuis l'adresse: %s\n", paddr)
		fmt.Printf("Socket connectée créée avec l'adresse %+v\n", paddr)*/
	
		//go handleSession(conn, mes, paddr, &identity, id, end)
		//si le pair est inconnu
		//créer une connection avec le pair
		//_, ok := knownaddr[paddr.String()]
		//if !ok {
		//	fmt.Println("Adresse inconnue, création d'une connection")
		//	knownaddr[paddr.String()] = true
		//	pconn, err := net.ListenUDP("udp", paddr)
		//	if err != nil {
		//		log.Fatal(err)
		//	}
		//	defer pconn.Close()

		//goroutine servant spécifiquement paddr
		//	go handleSession(pconn, mes, paddr, &identity, id, death)
		//}
		//si le channel kill est signalé
		//c'est que le pair n'a pas envoyé de Hello
		//(fait dans une goroutine pour ne pas bloquer le main)
		//go func() {
		//	kill := <-death
		//	fmt.Printf("Perte du pair %+v\n", kill)
		//	knownaddr[kill.String()] = false
		//}()
	}

}

//TODO
//HANDLE PACKET LOSS
