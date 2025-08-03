package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).

	Username string
	// sourceKey = the key used to derive the key to stuff in next layer
	PKEDec userlib.PKEDecKey
	DSSign userlib.DSSignKey
	// Has source key to access invitation pointers
	// Purpose = filename
	InvitationPointerSourceKey []byte
	ArrayOfFilenamesSourceKey  []byte
}

// Contains the metadata for the file
type File struct {
	// Has source key to access appends
	// Purpose = number of appends
	AppendSourceKey []byte
	Appends         int
}

// Points at the Invitation
type InvitationPointer struct {
	// Has source key to access invitations
	// Give others SourceInvitationKey in RSA Asymmetric
	// Purpose = "ObtainFile"
	InvitationSourceKey []byte
}

// Acts as the gateway between User struct and File struct
type Invitation struct {
	// Has source key to access file
	Valid bool
	Owner bool
	// Purpose = "ObtainInvitation"
	FileSourceKey []byte
	// If owner = false, then this will be nil
	// Purpose = "Map"
	NameToInvitationSourceKey []byte
}

// ---> ADD IN ERROR CHECKING AFTERWARDS <---
// Didn't add it yet, because code would be messy with a ton of if statements

// The next two helper methods ONLY apply to Symmetric Key Encryption/Decryption and HMAC
// Does not work for RSA Encryption/Decryption and Signatures

// Helper method that :
// Derive UUID and symmetric keys from sourceKey + purpose
// Encrypt and HMAC a byte array, and store it in Datastore
// Does not check for ANY returned errors, must implement later
func EncryptHMACUploadUsingSourceKey(plaintext []byte, sourceKey []byte, purpose []byte) (err error) {
	// Make sure that Source Key is 16 bytes
	if len(sourceKey) != 16 {
		return errors.New("Source Key must be 16 bytes long.")
	}
	// Generate UUID and encryption and HMAC keys
	QuadKeys, err := userlib.HashKDF(sourceKey, purpose)
	if err != nil {
		return errors.New("HashKDF did not work on Source Key.")
	}
	location, err := uuid.FromBytes(QuadKeys[0:16])
	if err != nil {
		return errors.New("Could not convert Bytes to UUID.")
	}
	encryptKey := QuadKeys[16:32]
	HMACKey := QuadKeys[32:48]
	// Encrypt and HMAC the message
	encrypted := userlib.SymEnc(encryptKey, userlib.RandomBytes(16), plaintext)
	HMAC, err := userlib.HMACEval(HMACKey, encrypted)
	if err != nil {
		return errors.New("HMAC didn't work on encrypted data.")
	}
	encryptedAndHMACed := append(encrypted, HMAC...)
	// Store it into StoreFile
	userlib.DatastoreSet(location, encryptedAndHMACed)
	return nil
}

// Helper method that :
// Derive a UUID and symmetric keys from sourceKey + purpose
// HMAC and decrypt a byte array, from Datastore
// Does not check for ALL returned errors, must implement later
func DownloadDecryptHMACUsingSourceKey(sourceKey []byte, purpose []byte) (plaintextReturned []byte, err error) {
	// Make sure that Source Key is 16 bytes
	if len(sourceKey) != 16 {
		return nil, errors.New("Source Key must be 16 bytes long.")
	}
	// Generate UUID and decryption and HMAC keys
	QuadKeys, err := userlib.HashKDF(sourceKey, purpose)
	if err != nil {
		return nil, errors.New("HashKDF did not work on Source Key.")
	}
	location, err := uuid.FromBytes(QuadKeys[0:16])
	if err != nil {
		return nil, errors.New("Could not convert Bytes to UUID.")
	}
	decryptKey := QuadKeys[16:32]
	HMACKey := QuadKeys[32:48]
	// Download the message from Storefile
	encryptedAndHMACed, ok := userlib.DatastoreGet(location)
	if ok == false {
		return nil, errors.New("Does not exist in Database.")
	}
	// Make sure message is at least 80 bytes long (16 for text, 64 for HMAC)
	if len(encryptedAndHMACed) < 80 {
		return nil, errors.New("Encrypted Data with HMAC should have at least 80 bytes.")
	}
	// Check the HMAC to make check integrity
	// HMAC is 64 bytes long
	encrypted := encryptedAndHMACed[:len(encryptedAndHMACed)-64]
	downloadedHMAC := encryptedAndHMACed[len(encryptedAndHMACed)-64:]
	expectedHMAC, err := userlib.HMACEval(HMACKey, encrypted)
	if err != nil {
		return nil, errors.New("Could not compute HMAC.")
	}
	notEdited := userlib.HMACEqual(downloadedHMAC, expectedHMAC)
	if notEdited == false {
		return nil, errors.New("Integrity could not be verified.")
	}
	// Decrypt the message
	plaintext := userlib.SymDec(decryptKey, encrypted)
	return plaintext, nil
}

// Real methods to implement
func InitUser(username string, password string) (userdataptr *User, err error) {
	// Check to to see if the username is already taken
	_, ok := userlib.KeystoreGet(username + "PKE")
	if ok == true {
		return nil, errors.New("Username already in use.")
	}

	if len(username) < 1 {
		return nil, errors.New("Username must be at least 1 character long.")
	}

	// Otherwise, create a new user struct to return
	var userdata User
	userdata.Username = username
	userdata.InvitationPointerSourceKey = userlib.RandomBytes(16)
	userdata.ArrayOfFilenamesSourceKey = userlib.RandomBytes(16)

	// Create and upload an empty array of File names
	var arraydata []string = make([]string, 0)
	arraydataByte, err := json.Marshal(arraydata)
	if err != nil {
		return nil, err
	}
	arrayByte, err := json.Marshal("Array")
	if err != nil {
		return nil, err
	}
	err = EncryptHMACUploadUsingSourceKey(arraydataByte, userdata.ArrayOfFilenamesSourceKey, arrayByte)
	if err != nil {
		return nil, err
	}

	// use Argon2Key to generate a Source Key
	// Use json.Marshal to convert from string to []byte
	usernameByte, err := json.Marshal(username)
	if err != nil {
		return nil, err
	}
	passwordByte, err := json.Marshal(password)
	if err != nil {
		return nil, err
	}
	sourceKey := userlib.Argon2Key(passwordByte, usernameByte, 16)

	// Generate the public and private keys for RSA
	PKEEnc, PKEDec, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	DSSign, DSVerify, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	// Store public encryption and public signature verification in Keystore
	err = userlib.KeystoreSet(username+"PKE", PKEEnc)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"DS", DSVerify)
	if err != nil {
		return nil, err
	}
	// Store private decryption and private signature generation key in User
	userdata.PKEDec = PKEDec
	userdata.DSSign = DSSign

	// Get the purpose and plaintext, will use "StoreUser" as the purpose for storing/retrieving users
	storedUserByte, err := json.Marshal("StoredUser")
	if err != nil {
		return nil, err
	}
	userdataByte, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	// Upload to Datastore
	err = EncryptHMACUploadUsingSourceKey(userdataByte, sourceKey, storedUserByte)
	if err != nil {
		return nil, err
	}

	// return the new user struct
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Check to to see if the username exists in Keystore
	_, ok := userlib.KeystoreGet(username + "PKE")
	if ok == false {
		return nil, errors.New("User does not exist.")
	}

	// use Argon2Key to generate a Source Key
	usernameByte, err := json.Marshal(username)
	if err != nil {
		return nil, err
	}
	passwordByte, err := json.Marshal(password)
	if err != nil {
		return nil, err
	}
	sourceKey := userlib.Argon2Key(passwordByte, usernameByte, 16)

	// Generate UUID and encryption and HMAC keys
	storedUserByte, err := json.Marshal("StoredUser")
	if err != nil {
		return nil, err
	}
	// Download the data from Datastore
	plaintext, err := DownloadDecryptHMACUsingSourceKey(sourceKey, storedUserByte)
	if err != nil {
		return nil, errors.New("Incorrect Username and Password.")
	}

	// Unmarshal and return object
	var userdata User
	err = json.Unmarshal(plaintext, &userdata)
	if err != nil {
		return nil, err
	}
	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// encryptKeyOfX = the key used to encrypt X
	// sourceEncryptKeyOfX = the key used to derive the key to encrypt X

	// Convert filename into bytes
	filenameByte, err := json.Marshal(filename)
	if err != nil {
		return err
	}
	// Download the invitation pointer plaintext from Datastore
	// Cannot use the DownloadDecryptHMACUsingSourceKey helper function, because we have to specifically check if the file exists
	// Generate UUID and decryption and HMAC keys
	QuadKeys, err := userlib.HashKDF(userdata.InvitationPointerSourceKey, filenameByte)
	if err != nil {
		return err
	}
	location, err := uuid.FromBytes(QuadKeys[0:16])
	if err != nil {
		return err
	}
	decryptKey := QuadKeys[16:32]
	HMACKey := QuadKeys[32:48]
	// Download the message from Storefile, where ok represents if we can find something
	encryptedAndHMACed, ok := userlib.DatastoreGet(location)

	// These will be setup in the if-else loop, that will later be used afterwards to upload stuff
	var sourceKeyOfAppend []byte
	var sourceKeyOfFile []byte
	var sourceKeyOfInvitation []byte
	obtainInvitationByte, err := json.Marshal("ObtainInvitation")
	if err != nil {
		return err
	}
	// Special case of having Invitation struct here, because if file is brand new then need a master invitation file
	var newinvitationdata Invitation
	// If File already exists, then use the previous sourceKeys instead of making new ones
	// Download all three layers to retrieve the original keys
	if ok == true {

		// Unencrypt and verify the file
		// Check the HMAC to make check integrity
		// HMAC is 64 bytes long
		encrypted := encryptedAndHMACed[:len(encryptedAndHMACed)-64]
		downloadedHMAC := encryptedAndHMACed[len(encryptedAndHMACed)-64:]
		expectedHMAC, err := userlib.HMACEval(HMACKey, encrypted)
		if err != nil {
			return err
		}
		notEdited := userlib.HMACEqual(downloadedHMAC, expectedHMAC)
		if notEdited == false {
			return errors.New("Integrity could not be verified.")
		}
		// Decrypt the Invitation Pointer plaintext
		originalInvitationPointerPlaintext := userlib.SymDec(decryptKey, encrypted)
		// Unmarshal the Invitation Pointer
		var originalinvitationpointerdata InvitationPointer
		err = json.Unmarshal(originalInvitationPointerPlaintext, &originalinvitationpointerdata)
		if err != nil {
			return err
		}

		// Download the Invitation plaintext from Datastore
		originalInvitationPlaintext, err := DownloadDecryptHMACUsingSourceKey(originalinvitationpointerdata.InvitationSourceKey, obtainInvitationByte)
		// Compiler complaining about declaring but not using "err" variable for some reason
		if err != nil {
			return err
		}
		// Unmarshal the Invitation
		var originalinvitationdata Invitation
		err = json.Unmarshal(originalInvitationPlaintext, &originalinvitationdata)
		if err != nil {
			return err
		}

		// Download the File from Datastore
		obtainFileByte, err := json.Marshal("ObtainFile")
		if err != nil {
			return err
		}
		filePlaintext, err := DownloadDecryptHMACUsingSourceKey(originalinvitationdata.FileSourceKey, obtainFileByte)
		if err != nil {
			return err
		}
		// Unmarshal the file
		var filedata File
		err = json.Unmarshal(filePlaintext, &filedata)
		if err != nil {
			return err
		}

		// Clear out the old appends in Datastore
		// Iterate through the number of appends and delete every thing
		var appendNum []byte
		for i := 0; i < filedata.Appends; i++ {
			// Grab the location of each Append
			appendNum, err = json.Marshal(i)
			if err != nil {
				return err
			}
			locationAppendKey, err := userlib.HashKDF(filedata.AppendSourceKey, appendNum)
			if err != nil {
				return errors.New("HashKDF did not work on Source Key.")
			}
			location, err := uuid.FromBytes(locationAppendKey[0:16])
			if err != nil {
				return err
			}
			// Delete the Append
			userlib.DatastoreDelete(location)
		}

		// Use old values instead of remaking new ones
		sourceKeyOfAppend = filedata.AppendSourceKey
		sourceKeyOfFile = originalinvitationdata.FileSourceKey
		sourceKeyOfInvitation = originalinvitationpointerdata.InvitationSourceKey

		// Just make the same invitation to upload
		newinvitationdata.FileSourceKey = originalinvitationdata.FileSourceKey
		newinvitationdata.Owner = originalinvitationdata.Owner
		newinvitationdata.Valid = originalinvitationdata.Valid
		newinvitationdata.NameToInvitationSourceKey = originalinvitationdata.NameToInvitationSourceKey

		// If File doesn't exist, then create new sourceKeys
		// Logically, you must be the owner, because the file does not exist which means it couldn't have been shared to you
	} else if ok == false {
		// First check if you've seen the file before, to make sure that adversary didn't delete your Invitation Pointer
		// Download the array of seen files
		arrayByte, err := json.Marshal("Array")
		if err != nil {
			return err
		}
		arrayPlaintext, err := DownloadDecryptHMACUsingSourceKey(userdata.ArrayOfFilenamesSourceKey, arrayByte)
		if err != nil {
			return err
		}
		var arraydata []string
		err = json.Unmarshal(arrayPlaintext, &arraydata)
		if err != nil {
			return err
		}
		// Check if filename is in your seen files
		for _, element := range arraydata {
			if element == filename {
				return errors.New("Adversary deleted an Invitation Pointer Struct.")
			}
		}
		// Once you are sure that you haven't seen the file before, add it to be seen
		// Edit the array to include the filename
		arraydata = append(arraydata, filename)
		arraydataByte, err := json.Marshal(arraydata)
		if err != nil {
			return err
		}
		// Upload the array back to Datastore
		err = EncryptHMACUploadUsingSourceKey(arraydataByte, userdata.ArrayOfFilenamesSourceKey, arrayByte)
		if err != nil {
			return err
		}

		// Generate random Source Keys for the Appends, File, and Invitation
		sourceKeyOfAppend = userlib.RandomBytes(16)
		sourceKeyOfFile = userlib.RandomBytes(16)
		sourceKeyOfInvitation = userlib.RandomBytes(16)

		// Store the Source Key of File in master Invitation Struct
		newinvitationdata.FileSourceKey = sourceKeyOfFile
		newinvitationdata.Valid = true
		// Set owner to be true
		newinvitationdata.Owner = true
		// Create a dictionary with your own name linked to the master invitation
		var dictionary map[string][]byte = make(map[string][]byte)
		dictionary[userdata.Username] = sourceKeyOfInvitation
		dictionaryByte, err := json.Marshal(dictionary)
		if err != nil {
			return err
		}
		// Create the Source Key to access the dictionary and store it in the master invitation
		mapByte, err := json.Marshal("Map")
		if err != nil {
			return err
		}
		newinvitationdata.NameToInvitationSourceKey = userlib.RandomBytes(16)
		// Upload this dictionary
		err = EncryptHMACUploadUsingSourceKey(dictionaryByte, newinvitationdata.NameToInvitationSourceKey, mapByte)
		if err != nil {
			return err
		}
	}

	// Store the Source Key for Appends in the File Struct
	var filedata File
	filedata.AppendSourceKey = sourceKeyOfAppend
	filedata.Appends = 0

	// Store the Source Key of File in Invitation
	// Handled above in if else case, due to case of whether to create a new file and new master invitation
	// or to just overwrite current file contents

	// Store the Source Key of Invitation in Invitation Pointer
	var invitationpointerdata InvitationPointer
	invitationpointerdata.InvitationSourceKey = sourceKeyOfInvitation

	// Place the content/text of the File into DataStore
	// Will use number of appends as the "purpose" for each key
	appendsByte, err := json.Marshal(0)
	if err != nil {
		return err
	}
	err = EncryptHMACUploadUsingSourceKey(content, sourceKeyOfAppend, appendsByte)
	if err != nil {
		return err
	}

	// Remember to index the number of appends before storing File
	filedata.Appends = filedata.Appends + 1
	// Store the File into Datastore
	obtainFileByte, err := json.Marshal("ObtainFile")
	if err != nil {
		return err
	}
	fileByte, err := json.Marshal(filedata)
	if err != nil {
		return err
	}
	err = EncryptHMACUploadUsingSourceKey(fileByte, sourceKeyOfFile, obtainFileByte)
	if err != nil {
		return err
	}

	// Store the invitation into Datastore
	invitationByte, err := json.Marshal(newinvitationdata)
	if err != nil {
		return err
	}
	err = EncryptHMACUploadUsingSourceKey(invitationByte, sourceKeyOfInvitation, obtainInvitationByte)
	if err != nil {
		return err
	}

	// Store the invitation pointer into Datastore
	invitationPointerByte, err := json.Marshal(invitationpointerdata)
	if err != nil {
		return err
	}
	err = EncryptHMACUploadUsingSourceKey(invitationPointerByte, userdata.InvitationPointerSourceKey, filenameByte)
	if err != nil {
		return err
	}

	// Return nil
	return nil
}

// Make sure to use a constant bandwidth
func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Convert filename
	filenameByte, err := json.Marshal(filename)
	if err != nil {
		return err
	}
	// Download the Invitation Pointer plaintext from Datastore
	invitationPointerPlaintext, err := DownloadDecryptHMACUsingSourceKey(userdata.InvitationPointerSourceKey, filenameByte)
	if err != nil {
		return err
	}
	// Unmarshal the Invitation Pointer
	var invitationpointerdata InvitationPointer
	err = json.Unmarshal(invitationPointerPlaintext, &invitationpointerdata)
	if err != nil {
		return err
	}

	// Download the Invitation plaintext from Datastore
	obtainInvitationByte, err := json.Marshal("ObtainInvitation")
	if err != nil {
		return err
	}
	invitationPlaintext, err := DownloadDecryptHMACUsingSourceKey(invitationpointerdata.InvitationSourceKey, obtainInvitationByte)
	if err != nil {
		return err
	}
	// Unmarshal the Invitation
	var invitationdata Invitation
	err = json.Unmarshal(invitationPlaintext, &invitationdata)
	if err != nil {
		return err
	}

	// Check invitation to see if you still have access
	if invitationdata.Valid == false {
		return errors.New("Access has been revoked.")
	}

	// Download the File from Datastore
	obtainFileByte, err := json.Marshal("ObtainFile")
	if err != nil {
		return err
	}
	filePlaintext, err := DownloadDecryptHMACUsingSourceKey(invitationdata.FileSourceKey, obtainFileByte)
	if err != nil {
		return err
	}
	// Unmarshal the file
	var filedata File
	err = json.Unmarshal(filePlaintext, &filedata)
	if err != nil {
		return err
	}

	// Place the content/text of the File into DataStore
	// Will use number of appends as the "purpose" for each key
	appendsByte, err := json.Marshal(filedata.Appends)
	if err != nil {
		return err
	}
	err = EncryptHMACUploadUsingSourceKey(content, filedata.AppendSourceKey, appendsByte)
	if err != nil {
		return err
	}

	// Remember to index the number of appends before storing
	filedata.Appends += 1
	// Place edited File Struct back into Datastore
	fileByte, err := json.Marshal(filedata)
	if err != nil {
		return err
	}
	err = EncryptHMACUploadUsingSourceKey(fileByte, invitationdata.FileSourceKey, obtainFileByte)
	if err != nil {
		return err
	}
	// return nil
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Convert filename and content into bytes
	filenameByte, err := json.Marshal(filename)
	if err != nil {
		return nil, err
	}

	// Download the invitation pointer plaintext from Datastore
	invitationPointerPlaintext, err := DownloadDecryptHMACUsingSourceKey(userdata.InvitationPointerSourceKey, filenameByte)
	if err != nil {
		return nil, err
	}
	// Unmarshal the Invitation Pointer
	var invitationpointerdata InvitationPointer
	err = json.Unmarshal(invitationPointerPlaintext, &invitationpointerdata)
	if err != nil {
		return nil, err
	}

	// Download the invitation plaintext from Datastore
	obtainInvitationByte, err := json.Marshal("ObtainInvitation")
	if err != nil {
		return nil, err
	}
	invitationPlaintext, err := DownloadDecryptHMACUsingSourceKey(invitationpointerdata.InvitationSourceKey, obtainInvitationByte)
	if err != nil {
		return nil, err
	}
	// Unmarshal the Invitation
	var invitationdata Invitation
	err = json.Unmarshal(invitationPlaintext, &invitationdata)
	if err != nil {
		return nil, err
	}

	// Check invitation to see if you still have access
	if invitationdata.Valid == false {
		return nil, errors.New("Access has been revoked.")
	}

	// Download the File from Datastore
	obtainFileByte, err := json.Marshal("ObtainFile")
	if err != nil {
		return nil, err
	}
	filePlaintext, err := DownloadDecryptHMACUsingSourceKey(invitationdata.FileSourceKey, obtainFileByte)
	if err != nil {
		return nil, err
	}
	// Unmarshal the file
	var filedata File
	err = json.Unmarshal(filePlaintext, &filedata)
	if err != nil {
		return nil, err
	}

	// Iterate through the number of appends and download every thing
	var purpose []byte
	var plaintext []byte
	var toReturn []byte = []byte{}
	for i := 0; i < filedata.Appends; i++ {
		purpose, err = json.Marshal(i)
		if err != nil {
			return nil, err
		}
		plaintext, err = DownloadDecryptHMACUsingSourceKey(filedata.AppendSourceKey, purpose)
		if err != nil {
			return nil, err
		}
		// Combine toReturn and the newly read data, and go to next iteration
		toReturn = append(toReturn, plaintext...)
	}
	return toReturn, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// Convert filename and content into bytes
	filenameByte, err := json.Marshal(filename)
	if err != nil {
		return uuid.Nil, err
	}

	// Download the invitation pointer plaintext from Datastore
	invitationPointerPlaintext, err := DownloadDecryptHMACUsingSourceKey(userdata.InvitationPointerSourceKey, filenameByte)
	if err != nil {
		return uuid.Nil, err
	}
	// Unmarshal the Invitation Pointer
	var invitationpointerdata InvitationPointer
	err = json.Unmarshal(invitationPointerPlaintext, &invitationpointerdata)
	if err != nil {
		return uuid.Nil, err
	}

	// Download the invitation plaintext from Datastore
	obtainInvitationByte, err := json.Marshal("ObtainInvitation")
	if err != nil {
		return uuid.Nil, err
	}
	invitationPlaintext, err := DownloadDecryptHMACUsingSourceKey(invitationpointerdata.InvitationSourceKey, obtainInvitationByte)
	if err != nil {
		return uuid.Nil, err
	}
	// Unmarshal the Invitation
	var invitationdata Invitation
	err = json.Unmarshal(invitationPlaintext, &invitationdata)
	if err != nil {
		return uuid.Nil, err
	}

	// Check invitation to see if you still have access
	if invitationdata.Valid == false {
		return uuid.Nil, errors.New("Access has been revoked.")
	}

	// Grab the recipients public key for RSA encryption
	// Do this check before the if else block, otherwise we will create an invitation that we can't even share
	// Will grab your own private key for RSA signing after this if-else statement
	pubkeyenc, ok := userlib.KeystoreGet(recipientUsername + "PKE")
	if ok == false {
		return uuid.Nil, errors.New("User does not exist")
	}

	// Location to place the source key of invitation struct will just be random
	locationOfData := uuid.New()
	// This value is what will be shared to someone else using RSA encryption and signing
	// Non-owner shares their own, the owner will create a new one to share (do not share the master invitation)
	var invitationSourceKey []byte
	// If you are not the owner, then just use the Invitation Source Key of your own Invitation
	if invitationdata.Owner == false {
		invitationSourceKey = invitationpointerdata.InvitationSourceKey

		// If you are the owner, then have to do more work
	} else if invitationdata.Owner == true {
		// Create a new invitation struct
		var newinvitationdata Invitation
		newinvitationdata.Valid = true
		newinvitationdata.Owner = false
		newinvitationdata.FileSourceKey = invitationdata.FileSourceKey
		// Leave the dictionary of this Invitation as null, because only the owner should have it

		// Upload the newly created invitation to Datastore using a new Invitation Source Key
		newInvitationByte, err := json.Marshal(newinvitationdata)
		if err != nil {
			return uuid.Nil, err
		}
		newInvitationSourceKey := userlib.RandomBytes(16)
		err = EncryptHMACUploadUsingSourceKey(newInvitationByte, newInvitationSourceKey, obtainInvitationByte)
		if err != nil {
			return uuid.Nil, err
		}

		// Modify the dictionary of Direct Users to invitation source keys to include this new invitation
		// Download the original dictionary
		mapByte, err := json.Marshal("Map")
		if err != nil {
			return uuid.Nil, err
		}
		dictionaryPlaintext, err := DownloadDecryptHMACUsingSourceKey(invitationdata.NameToInvitationSourceKey, mapByte)
		if err != nil {
			return uuid.Nil, err
		}
		var dictionary map[string][]byte
		err = json.Unmarshal(dictionaryPlaintext, &dictionary)
		if err != nil {
			return uuid.Nil, err
		}
		// Edit it to include the new invitation
		dictionary[recipientUsername] = newInvitationSourceKey
		// Upload the edited dictionary back to Datastore
		dictionaryByte, err := json.Marshal(dictionary)
		if err != nil {
			return uuid.Nil, err
		}
		err = EncryptHMACUploadUsingSourceKey(dictionaryByte, invitationdata.NameToInvitationSourceKey, mapByte)
		if err != nil {
			return uuid.Nil, err
		}

		// Use this new Invitation Source Key
		invitationSourceKey = newInvitationSourceKey
	}

	// Already grabbed the recipients public key for RSA encryption
	// Grab your own private key for RSA signing
	privkeysign := userdata.DSSign
	encrypted, err := userlib.PKEEnc(pubkeyenc, invitationSourceKey)
	if err != nil {
		return uuid.Nil, err
	}
	signature, err := userlib.DSSign(privkeysign, encrypted)
	if err != nil {
		return uuid.Nil, err
	}
	encryptedAndSigned := append(encrypted, signature...)
	// Store the source key of invitation struct at random UUID
	userlib.DatastoreSet(locationOfData, encryptedAndSigned)
	return locationOfData, nil
}

// Watch for edge case of calling accept invitation randomly
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	// Download the array of seen files
	arrayByte, err := json.Marshal("Array")
	if err != nil {
		return err
	}
	arrayPlaintext, err := DownloadDecryptHMACUsingSourceKey(userdata.ArrayOfFilenamesSourceKey, arrayByte)
	if err != nil {
		return err
	}
	var arraydata []string
	err = json.Unmarshal(arrayPlaintext, &arraydata)
	if err != nil {
		return err
	}
	// Check if filename is in your seen files, and error if you have
	for _, element := range arraydata {
		if element == filename {
			return errors.New("You already have a file named that.")
		}
	}

	// Grab the sender's public key for RSA signature verification
	pubkeysign, ok := userlib.KeystoreGet(senderUsername + "DS")
	if ok == false {
		return errors.New("Sender does not exist.")
	}
	// Grab your own private key for RSA decryption
	privkeydec := userdata.PKEDec

	// Download the encrypted and signed Invitation
	// invitationPtr = the UUID of shared information, it is NOT an Invitation Pointer struct
	encryptedAndSigned, ok := userlib.DatastoreGet(invitationPtr)
	if ok == false {
		return errors.New("No invitation at that location.")
	}

	// Make sure message is at least 256 bytes long, for the Digital Signature
	// Not sure if PKEDec has a minimum length requirement though
	if len(encryptedAndSigned) < 256 {
		return errors.New("Encrypted Data with Digital Signature should have at least 80 bytes.")
	}

	// Check the signature to make check integrity
	// RSA signature is 256-bytes
	encrypted := encryptedAndSigned[:len(encryptedAndSigned)-256]
	downloadedSignature := encryptedAndSigned[len(encryptedAndSigned)-256:]
	validSig := userlib.DSVerify(pubkeysign, encrypted, downloadedSignature)
	if validSig != nil {
		return errors.New("Integrity could not be verified.")
	}
	// Decrypt the message
	invitationSourceKey, err := userlib.PKEDec(privkeydec, encrypted)
	if err != nil {
		return errors.New("Ciphertext could not be decrypted.")
	}

	// Check to see the Invitation has been revoked or not
	// Download the invitation plaintext from Datastore
	obtainInvitationByte, err := json.Marshal("ObtainInvitation")
	if err != nil {
		return err
	}
	invitationPlaintext, err := DownloadDecryptHMACUsingSourceKey(invitationSourceKey, obtainInvitationByte)
	if err != nil {
		return err
	}
	// Unmarshal the Invitation
	var invitationdata Invitation
	err = json.Unmarshal(invitationPlaintext, &invitationdata)
	if err != nil {
		return err
	}
	// Check if the Invitation has been revoked
	if invitationdata.Valid == false {
		return errors.New("Invitation has been revoked, cannot accept Invitation. ")
	}

	// Store the Invitation Source Key inside of an Invitation Pointer
	var invitationpointerdata InvitationPointer
	invitationpointerdata.InvitationSourceKey = invitationSourceKey

	// Upload the new Invitation Pointer to Datastore
	invitationPointerByte, err := json.Marshal(invitationpointerdata)
	if err != nil {
		return err
	}
	filenameByte, err := json.Marshal(filename)
	if err != nil {
		return err
	}
	err = EncryptHMACUploadUsingSourceKey(invitationPointerByte, userdata.InvitationPointerSourceKey, filenameByte)
	if err != nil {
		return err
	}

	// Already downloaded the array of files at start of function
	// Edit the array to include the filename
	arraydata = append(arraydata, filename)
	arraydataByte, err := json.Marshal(arraydata)
	if err != nil {
		return err
	}
	// Upload the array back to Datastore
	err = EncryptHMACUploadUsingSourceKey(arraydataByte, userdata.ArrayOfFilenamesSourceKey, arrayByte)
	if err != nil {
		return err
	}

	// Delete the invitation from Datastore
	userlib.DatastoreDelete(invitationPtr)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Can't revoke yourself
	if userdata.Username == recipientUsername {
		return errors.New("Cannot revoke yourself.")
	}

	// Convert filename and content into bytes
	filenameByte, err := json.Marshal(filename)
	if err != nil {
		return errors.New("Could not Marshal.")
	}

	// Download the Invitation Pointer plaintext from Datastore
	invitationPointerPlaintext, err := DownloadDecryptHMACUsingSourceKey(userdata.InvitationPointerSourceKey, filenameByte)
	if err != nil {
		return err
	}
	// Unmarshal the Invitation Pointer
	var invitationpointerdata InvitationPointer
	err = json.Unmarshal(invitationPointerPlaintext, &invitationpointerdata)
	if err != nil {
		return err
	}

	// Download the Invitation plaintext from Datastore
	obtainInvitationByte, err := json.Marshal("ObtainInvitation")
	if err != nil {
		return err
	}
	invitationPlaintext, err := DownloadDecryptHMACUsingSourceKey(invitationpointerdata.InvitationSourceKey, obtainInvitationByte)
	if err != nil {
		return err
	}
	// Unmarshal the Invitation
	var masterinvitationdata Invitation
	err = json.Unmarshal(invitationPlaintext, &masterinvitationdata)
	if err != nil {
		return err
	}

	// Check invitation to see if you're the owner
	if masterinvitationdata.Owner == false {
		return errors.New("You are not the owner of the file, so you cannot revoke others.")
	}

	// Then check if the invitation exists
	mapByte, err := json.Marshal("Map")
	if err != nil {
		return err
	}
	dictionaryByte, err := DownloadDecryptHMACUsingSourceKey(masterinvitationdata.NameToInvitationSourceKey, mapByte)
	if err != nil {
		return err
	}
	var dictionary map[string][]byte
	err = json.Unmarshal(dictionaryByte, &dictionary)
	if err != nil {
		return err
	}
	if _, exists := dictionary[recipientUsername]; !exists {
		return errors.New("The recipient does not have an invitation to revoke.")
	}

	// If you're the owner, then have to rebuild the file and and edit invitations

	// First, obtain all of the file contents using the LoadFile function from earlier
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}
	// Clear out the old appends and File in Datastore
	// Download the File from Datastore
	obtainFileByte, err := json.Marshal("ObtainFile")
	if err != nil {
		return err
	}
	originalFilePlaintext, err := DownloadDecryptHMACUsingSourceKey(masterinvitationdata.FileSourceKey, obtainFileByte)
	if err != nil {
		return err
	}
	// Unmarshal the file
	var originalfiledata File
	err = json.Unmarshal(originalFilePlaintext, &originalfiledata)
	if err != nil {
		return err
	}
	// Iterate through the number of appends and delete every thing
	var appendNum []byte
	for i := 0; i < originalfiledata.Appends; i++ {
		// Grab the location of each Append
		appendNum, err = json.Marshal(i)
		if err != nil {
			return err
		}
		locationAppendKey, err := userlib.HashKDF(originalfiledata.AppendSourceKey, appendNum)
		if err != nil {
			return err
		}
		location, err := uuid.FromBytes(locationAppendKey[0:16])
		if err != nil {
			return err
		}
		// Delete the Append
		userlib.DatastoreDelete(location)
	}

	// Delete the old File
	locationFileKey, err := userlib.HashKDF(masterinvitationdata.FileSourceKey, obtainFileByte)
	if err != nil {
		return err
	}
	locationFile, err := uuid.FromBytes(locationFileKey[0:16])
	if err != nil {
		return err
	}
	userlib.DatastoreDelete(locationFile)

	// Then, recreate the File struct
	var filedata File
	filedata.AppendSourceKey = userlib.RandomBytes(16)
	filedata.Appends = 0
	// Place the content/text of the File into DataStore
	// Will use number of appends as the "purpose" for each key
	appendsByte, err := json.Marshal(0)
	if err != nil {
		return err
	}
	err = EncryptHMACUploadUsingSourceKey(content, filedata.AppendSourceKey, appendsByte)
	if err != nil {
		return err
	}

	// Remember to increment number of appends of File
	filedata.Appends = 1
	// Create a new File Source Key to get UUID and symmetric keys of file
	newFileSourceKey := userlib.RandomBytes(16)
	// Upload the new File Struct using this new File Source Key
	fileByte, err := json.Marshal(filedata)
	if err != nil {
		return err
	}
	err = EncryptHMACUploadUsingSourceKey(fileByte, newFileSourceKey, obtainFileByte)
	if err != nil {
		return err
	}

	// Now we need to edit the invitations of those who are not revoked
	var newinvitationdata Invitation
	// Iterate through the dictionary of shared users, which includes the master invitation
	for name, invitationSourceKey := range dictionary {
		// Download the Invitation associated with the Username
		newInvitationPlaintext, err := DownloadDecryptHMACUsingSourceKey(invitationSourceKey, obtainInvitationByte)
		if err != nil {
			return err
		}
		err = json.Unmarshal(newInvitationPlaintext, &newinvitationdata)
		if err != nil {
			return err
		}
		// If we are not trying to revoke this person, then edit their invitation to have the new File Source Key
		if name != recipientUsername {
			newinvitationdata.FileSourceKey = newFileSourceKey
			// If we are trying to revoke this person, then edit their invitation to be invalid
		} else if name == recipientUsername {
			newinvitationdata.Valid = false
		}
		// Upload the edited Invitation to Datastore
		newInvitationDataByte, err := json.Marshal(newinvitationdata)
		if err != nil {
			return err
		}
		err = EncryptHMACUploadUsingSourceKey(newInvitationDataByte, invitationSourceKey, obtainInvitationByte)
		if err != nil {
			return err
		}
	}

	// Delete the revoked User from the dictionary
	delete(dictionary, recipientUsername)
	// Upload the dictionary to Datastore
	dictionaryByte, err = json.Marshal(dictionary)
	if err != nil {
		return err
	}
	err = EncryptHMACUploadUsingSourceKey(dictionaryByte, masterinvitationdata.NameToInvitationSourceKey, mapByte)
	if err != nil {
		return err
	}

	return nil
}
