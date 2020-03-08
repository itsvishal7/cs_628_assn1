package assn1

import (
	"github.com/fenilfadadu/CS628-assn1/userlib"
	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//List_File Structure
type ListF struct {
	Dict map[string]ListFData
}

type ListFData struct {
	MetaLoc string
	Owner bool
}

//Meta_File Structure
type Meta struct {
	Pointers []string
	Collabs []string
}

//File struture
type File struct {
	Eval []byte
	Hval []byte
}

// The structure definition for a user record
type User struct {
	Username string
	Shadow string
	PrivateKey *userlib.PrivateKey
	Location string
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	userdata.Shadow = getSHA256Hash(username+password) 		//getSHA256Hash(s string) (hash string)
	userdata.Location = getRandomLocation() 				// loc for ListFile (returns string type)

	//defining empty ListF struct so as to store at loc generated above
	var listF ListF
	listF.Dict = make(map[string]ListFData)

	//(userdata *User) saveListF(listF ListF) (err error)
	err = userdata.saveListF(listF)
	if err != nil {
		return nil, errors.New("InitUser:1: "+err.Error())
	}

	// Generating Public-Private Key pair and then storing respectively
	key, err := userlib.GenerateRSAKey()
	if err != nil {
		return nil , errors.New("InitUser:2: "+err.Error())
	}
	userdata.PrivateKey = key
	userlib.KeystoreSet(username, key.PublicKey)

	//Marshalling userdata into []byte
	data, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New("InitUser:3: "+err.Error())
	}

	//encode saves data in Datastore and return err or nil (depending)
	//encrypts data using loc then calculates HMAC using loc and cipher and hash at SHA256Hash(loc)
	//encode(data []byte, loc string) (err error)
	err = encode(data, password+username)
	if err != nil {
		return nil, errors.New("InitUser:4: "+err.Error())
	}
	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	//Getting User Data Struct from Datastore and Unmarshalling
	data, err := decode(password+username)
	if err != nil {
		return nil, errors.New("GetUser:1: "+err.Error())
	}
	var userdata User
	// Unmarshalling msgid(string) into []byte, then filling userdata struct accordingly
	err = json.Unmarshal(data, &userdata)
	if err != nil {
		return nil, errors.New("GetUser:2: "+err.Error())
	}
	
	//calculating shadow and checking authencity
	shadow := getSHA256Hash(username+password)//getSHA256Hash(s string) (hash string)
	if shadow != string(userdata.Shadow) {
		return nil, errors.New("GetUser:3: Invalid Credentials")
	}

	return &userdata, nil
}

// This stores a file in the datastore.
func (userdata *User) StoreFile(filename string, data []byte) {
	// (userdata *User) getListF() (listf ListF, err error)
	listf, err := userdata.getListF()
	if err != nil {
		return
	}

	// Does entry for filename exists?
	_, ok := listf.Dict[filename]
	if ok {
		// (listf *ListF) getMetaF(filename string) (meta Meta, err error)
		meta, err := listf.getMetaF(filename)
		if err != nil {
			return
		}
		//overwriting array
		meta.Pointers = make([]string, 0)
		meta.Pointers = append(meta.Pointers, getRandomLocation())

		//Overwrting File
		//encode(data []byte, loc string) (err error)
		err = encode(data, meta.Pointers[0])
		if err != nil {
			return
		}

		//(listf *ListF) saveMetaF(meta Meta, filename string) (err error)
		err = listf.saveMetaF(meta, filename)
		if err != nil {
			return
		}
		}else {
			var listFData ListFData
			listFData.MetaLoc = getRandomLocation() //returns string
			listFData.Owner = true
			listf.Dict[filename] = listFData

			var meta Meta
			meta.Pointers = append(meta.Pointers, getRandomLocation()) //append(array, array_element)
			meta.Collabs = append(meta.Collabs, userdata.Username)

			//encode(data []byte, loc string) (err error)
			err = encode(data, meta.Pointers[0])
			if err != nil {
				return
			}

			//(listf *ListF) saveMetaF(meta Meta, filename string) (err error)
			err = listf.saveMetaF(meta, filename)
			if err != nil {
				return
			}

			//(userdata *User) saveListF(listF ListF) (err error)
			err = userdata.saveListF(listf)
			if err != nil {
				return
			}
		}
	}

	// This adds on to an existing file.
	// Append should be efficient, you shouldn't rewrite or reencrypt the
	// existing file, but only whatever additional information and
	// metadata you need.

	func (userdata *User) AppendFile(filename string, data []byte) (err error) {
		//(userdata *User) getListF() (listF ListF, err error)
		listf, err := userdata.getListF()
		if err != nil {
			return errors.New("AppendFile:1: "+err.Error())
		}

		// If file does not exist, Store the file on datastore
		_, ok := listf.Dict[filename]
		if !ok {
			//(userdata *User) StoreFile(filename string, data []byte)
			userdata.StoreFile(filename, data)
			return nil
		}

		// (listf *ListF) getMetaF(filename string) (meta Meta, err error)
		meta, err := listf.getMetaF(filename)
		if err != nil{
			return errors.New("Appendfile:2: "+err.Error())
		}

		//Location for new data content
		loc := getRandomLocation()

		//encode(data []byte, loc string) (err error)
		err = encode(data, loc)
		if err != nil {
			return errors.New("AppendFile:3: "+err.Error())
		}

		meta.Pointers = append(meta.Pointers, loc) //append(array, array_element)

		//(listf *ListF) saveMetaF(meta Meta, filename string) (err error)
		err = listf.saveMetaF(meta, filename)
		if err != nil {
			return errors.New("AppendFile:4: "+err.Error())
		}

		return nil
	}

	// This loads a file from the Datastore.
	// It should give an error if the file is corrupted in any way.
	func (userdata *User) LoadFile(filename string) (data []byte, err error) {
		//(userdata *User) getListF() (listF ListF, err error)
		listf, err := userdata.getListF()
		if err != nil {
			return []byte(""), errors.New("LoadFile:1: "+err.Error())
		}

		//(listf *ListF) getMetaF(filename string) (meta Meta, err error)
		meta, err := listf.getMetaF(filename)
		if err != nil {
			return []byte(""), errors.New("LoadFile:2: "+err.Error())
		}

		//iteratively get all content files and append them together
		content := ""
		for _, locptr := range meta.Pointers {
			data, err := decode(locptr)
			if err != nil {
				return []byte(""), errors.New("LoadFile:3: "+err.Error())
			}
			content = content + string(data)
		}

		return []byte(content), nil
	}

	// You may want to define what you actually want to pass as a
	// sharingRecord to serialized/deserialize in the data store.
	type sharingRecord struct {
		Data string
		Sign string
	}

	// This creates a sharing record, which is a key pointing to something
	// in the datastore to share with the recipient.

	// This enables the recipient to access the encrypted file as well
	// for reading/appending.

	// Note that neither the recipient NOR the datastore should gain any
	// information about what the sender calls the file.  Only the
	// recipient can access the sharing record, and only the recipient
	// should be able to know the sender.

	func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
		//(userdata *User) getListF() (listF ListF, err error)
		listf, err := userdata.getListF()
		if err != nil{
			return "", errors.New("ShareFile:1: "+err.Error())
		}

		//Does entry for file exists or not?
		_, ok := listf.Dict[filename]
		if !ok {
			return "", errors.New("ShareFile:2: Entry for file: "+filename+" in listf.Dict")
		}

		// Does recipient exist?
		pubkey, ok := userlib.KeystoreGet(recipient)
		if !ok{
			return "", errors.New("ShareFile:3: Key corresponding to user: "+recipient+" not found")
		}

		//Get meta of the file
		//(listf *ListF) getMetaF(filename string) (meta Meta, err error)
		meta, err := listf.getMetaF(filename)
		if err != nil{
			return "", errors.New("ShareFile:4: "+err.Error())
		}

		// Checking whether file has already been shared
		flag := false
		for _,key := range meta.Collabs{
			if key == recipient {
				flag = true
				break
			}
		}
		if flag {
			return "", errors.New("ShareFile:5: File already shared with "+recipient+".")
		}

		//Preparing the values to be shared
		var share_record ListFData
		share_record.MetaLoc = listf.Dict[filename].MetaLoc
		share_record.Owner = false

		//Marshalling userdata into []byte
		data, err := json.Marshal(share_record)
		if err != nil{
			return "", errors.New("ShareFile:6: "+err.Error())
		}

		//(userdata *User) RSAEncrypt(&pubkey, data []byte, tag []byte) ([]byte, error)
		ciphertxt, err := userlib.RSAEncrypt(&pubkey, data, []byte("file"))
		if err != nil {
			return "", errors.New("ShareFile:7: "+err.Error())
		}

		//(userdata *User) RSASign(userdata.PrivateKey, data []byte) ([]byte, error)
		sign, err := userlib.RSASign(userdata.PrivateKey, ciphertxt)
		if err != nil {
			return "",errors.New("ShareFile:8: "+err.Error())
		}

		//Sharing Record
		var share sharingRecord
		share.Data = hex.EncodeToString(ciphertxt) //hex.EncodeToString([]byte) (string)
		share.Sign = hex.EncodeToString(sign)

		//Marshalling userdata into []byte
		share_bytes, err := json.Marshal(share)
		if err != nil{
			return "",errors.New("ShareFile:9: "+err.Error())
		}

		msgid = string(share_bytes) //returns string
		return msgid, nil
	}



	// Note recipient's filename can be different from the sender's filename.
	// The recipient should not be able to discover the sender's view on
	// what the filename even is!  However, the recipient must ensure that
	// it is authentically from the sender.
	func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
		pubkey, ok := userlib.KeystoreGet(sender)
		if !ok{
			return errors.New("ReceiveFile:1: Key corresponding to user: "+sender+" not found")
		}

		//(userdata *User) getListF() (listF ListF, err error)
		listf, err := userdata.getListF()
		if err != nil {
			return errors.New("ReceiveFile:2: "+err.Error())
		}

		//Does entry for filename already exists?
		_, ok = listf.Dict[filename]
		if ok && !listf.Dict[filename].Owner {
			return errors.New("ReceiveFile:3: Cannot receive file enrty already present")
		}

		var share sharingRecord
		// Unmarshalling msgid(string) into []byte, then filling share struct accordingly
		err = json.Unmarshal([]byte(msgid), &share)
		if err != nil {
			return errors.New("ReceiveFile:4: "+err.Error())
		}

		sign, err := hex.DecodeString(share.Sign) //returns []byte
		if err != nil{
			return errors.New("ReceiveFile:5: "+err.Error())
		}

		ciphertxt, err := hex.DecodeString(share.Data) //returns []byte
		if err != nil{
			return errors.New("ReceiveFile:6: "+err.Error())
		}

		// (userdata *User) RSAVerify(&pubkey, ciphertxt []byte, sign []byte)
		err = userlib.RSAVerify(&pubkey, ciphertxt, sign)
		if err != nil {
			return  errors.New("ReceiveFile:7: "+err.Error())
		}

		// (userdata *User) RSADecrypt(&pubkey, ciphertxt []byte, tag []byte)
		decrypt, err := userlib.RSADecrypt(userdata.PrivateKey, ciphertxt, []byte("file"))
		if err != nil {
			return errors.New("ReceiveFile:8: "+err.Error())
		}

		var filefdata ListFData
		// Unmarshalling msgid(string) into []byte, then filling filefdata struct accordingly
		err = json.Unmarshal(decrypt, &filefdata)
		if err != nil {
			return errors.New("ReceiveFile:9: "+err.Error())
		}

		// To store the filemeta into receiver's list of files
		var listfdata ListFData
		listfdata.MetaLoc = filefdata.MetaLoc
		listfdata.Owner = false
		listf.Dict[filename] = listfdata

		//(userdata *User) saveListF(listF ListF) (err error)
		err = userdata.saveListF(listf)
		if err != nil {
			return errors.New("ReceiveFile:10: "+err.Error())
		}

		//(listf *ListF) getMetaF(filename string) (meta Meta, err error)
		meta, err := listf.getMetaF(filename)
		if err != nil {
			return errors.New("ReceiveFile:11: "+err.Error())
		}

		// for Adding recipient to collaborators
		meta.Collabs = append(meta.Collabs, userdata.Username)

		//(listf *ListF) saveMetaF(meta Meta, filename string) (err error)
		err = listf.saveMetaF(meta, filename)
		if err != nil {
			return errors.New("ReceiveFile:12: "+err.Error())
		}

		return nil
	}

	// Removes access for all others.
	func (userdata *User) RevokeFile(filename string) (err error) {
		//(userdata *User) getListF() (listF ListF, err error)
		listf, err := userdata.getListF()
		if err != nil{
			return errors.New("RevokeFile:1: "+err.Error())
		}

		//To check whether the revoke called on filename is valid i.e. if the user has the file
		_, ok := listf.Dict[filename]
		if !ok {
			return errors.New("RevokeFile:2: Cannot Revoke! File Entry Absent!")
		}

		// To check is user calling revoke is the owner
		var listfdata ListFData
		listfdata = listf.Dict[filename]
		if !listfdata.Owner {
			return errors.New("RevokeFile:3: Cannot Revoke! Owners Only")
		}

		//(userdata *User) LoadFile(filename string) (data []byte, err error)
		bytes, err := userdata.LoadFile(filename)
		if err != nil {
			return errors.New("RevokeFile:4: "+err.Error())
		}

		//(listf *ListF) getMetaF(filename string) (meta Meta, err error)
		meta, err := listf.getMetaF(filename)
		if err != nil {
			return errors.New("RevokeFile:5: "+err.Error())
		}

		//To make sure same revoke file is not called without having collaborators
		count := 0
		for _,_ = range meta.Collabs{
			count = count+1
		}
		if count == 1 {
			return errors.New("RevokeFile:6: No collabrator")
		}

		// Delete MetaFile of file and its entry in listf.Dict
		userlib.DatastoreDelete(getSHA256Hash(listf.Dict[filename].MetaLoc)) //getSHA256Hash(s string) (hash string)
		delete(listf.Dict, filename)

		//(userdata *User) saveListF(listF ListF) (err error)
		err = userdata.saveListF(listf)
		if err != nil {
			return errors.New("RevokeFile:7: "+err.Error())
		}

		//(userdata *User) StoreFile(filename string, data []byte)
		userdata.StoreFile(filename, bytes)
		return nil
	}


	// Helper Functions

	func getRandomLocation() (loc string) {
		return uuid.New().String()
	}

	func getSHA256Hash(s string) (hash string){
		h := userlib.NewSHA256()
		h.Write([]byte(s))
		hash = hex.EncodeToString(h.Sum(nil))
		return
	}

	func getHMACHash(k string, msg string) (hash []byte) {
		data := []byte(msg)
		key := []byte(k)
		mac := userlib.NewHMAC(key)
		mac.Write(data)
		hash = mac.Sum(nil)
		return
	}

	func encode(data []byte, loc string) (error) {
		//check for authencity
		str := string(data)

		// encrypt(key string, msg string) (ciphertext []byte)
		cipher := encrypt(loc, str)
		//getHMACHash(key string, msg string) (hash []byte)
		hash := getHMACHash(loc, str)

		var f File
		f.Eval = cipher
		f.Hval = hash

		//Marshalling userdata into []byte
		val, err := json.Marshal(f)
		if err != nil {
			return errors.New("Encode:1: "+err.Error())
		}

		//Stores val at SHA256Hash(loc), getSHA256Hash(s string) (hash string)
		//DatastoreSet(key string, value []byte)
		userlib.DatastoreSet(getSHA256Hash(loc), val)
		return nil
	}

	// return data after decrypting and checking for integrity
	func decode(loc string) (data []byte, err error) {
		//getSHA256Hash(s string) (hash string)
		//DatastoreGet(key string) (value []byte, ok bool)
		value, valid := userlib.DatastoreGet(getSHA256Hash(loc))
		if !valid {
			return nil, errors.New("Decode:1: DatastoreGet Failed: Invalid Key")
		}

		var f File
		// Unmarshalling msgid(string) into []byte, then filling f struct accordingly
		err = json.Unmarshal(value, &f)
		if err != nil {
			return nil, errors.New("Decode:2: "+err.Error())
		}

		//decrypt(key string, ciphertext []byte) (plaintxt []byte)
		data = decrypt(loc, f.Eval)

		//getHMACHash(key string, msg string) (hash []byte)
		hash := getHMACHash(loc, string(data))

		if string(hash) != string(f.Hval) {
			return nil, errors.New("Decode:4: Data Integrity Check Failed!")
		}

		return data, nil
	}

	func encrypt(k string, msg string) (ciphertext []byte) {
		key := []byte(k + "NothingJustPlayingAround")[:16]
		ciphertext = make([]byte, userlib.BlockSize+len(msg))
		iv := ciphertext[:userlib.BlockSize]
		copy(iv, userlib.RandomBytes(userlib.BlockSize))
		cipher := userlib.CFBEncrypter(key, iv)
		cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(msg))
		return
	}

	func decrypt(k string, ciphertext []byte) (plaintxt []byte) {
		key := []byte(k + "NothingJustPlayingAround")[:16]
		iv := ciphertext[:userlib.BlockSize]

		cipher := userlib.CFBDecrypter(key, iv)
		cipher.XORKeyStream(ciphertext[userlib.BlockSize:], ciphertext[userlib.BlockSize:])

		return ciphertext[userlib.BlockSize:]
	}

	func (userdata *User) getListF() (listF ListF, err error) {
		//decode(loc string) (data []byte, err error)
		value, err := decode(userdata.Location)
		if err != nil {
			return listF, errors.New("getListF:1: "+err.Error())
		}
		// Unmarshalling msgid(string) into []byte, then filling listF struct accordingly
		err = json.Unmarshal(value, &listF)
		if err != nil {
			return listF, errors.New("getListF:2: "+err.Error())
		}
		return listF, nil
	}

	func (userdata *User) saveListF(listF ListF) (err error) {
		//Marshalling userdata into []byte
		data, err := json.Marshal(listF)
		if err != nil {
			return errors.New("saveListF:1: "+err.Error())
		}

		// encodes and saves data in Datastore and return whether successful or not
		//encode(data []byte, loc string) (err error)
		err = encode(data, userdata.Location)
		if err != nil {
			return errors.New("saveListF:2: "+err.Error())
		}
		return nil
	}

	func (listf *ListF) getMetaF(filename string) (meta Meta, err error) {
		//decode(loc string) (data []byte, err error)
		value, err := decode(listf.Dict[filename].MetaLoc)
		if err != nil {
			return meta, errors.New("getMetaF:1: "+err.Error())
		}

		// Unmarshalling msgid(string) into []byte, then filling meta struct accordingly
		err = json.Unmarshal(value, &meta)
		if err != nil {
			return meta, errors.New("getMetaF:2: "+err.Error())
		}
		return meta, nil
	}


	func (listf *ListF) saveMetaF(meta Meta, filename string) (err error) {
		//Marshalling userdata into []byte
		data, err := json.Marshal(meta)
		if err != nil {
			return errors.New("saveMetaF:1: "+err.Error())
		}

		//encode(data []byte, loc string) (err error)
		err = encode(data, listf.Dict[filename].MetaLoc)
		if err != nil {
			return errors.New("saveMetaF:2: "+err.Error())
		}
		return nil
	}
