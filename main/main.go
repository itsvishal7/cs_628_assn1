package main

import (
	"fmt"
	"cs628_assn1/assn1"
)


func main() {
	
	// User1
	username := "Ross Gellar"
	password := "password"
	_, err := assn1.InitUser(username, password)
        if err != nil {
                fmt.Println("Unable to create user")
                return
        }

	ross, err := assn1.GetUser(username, password)
        if err != nil {
                fmt.Println("GetUser call failed!")
                return
        }

    // USer 2    
	user2 := "Chandler"
	pass := "password"
	_, err = assn1.InitUser(user2, pass)
	if err != nil {
		fmt.Println("Unable to create user")
		return
	}

	chandler, err := assn1.GetUser(user2, pass)
	if err != nil {
                fmt.Println("GetUser call failed!")
                return
        }

    // User3 
    user3 := "Chand"
	pass = "password"
	_, err = assn1.InitUser(user3, pass)
	if err != nil {
		fmt.Println("Unable to create user")
		return
	}

	chand, err := assn1.GetUser(user3, pass)
	if err != nil {
                fmt.Println("GetUser call failed!")
                return
        }   

	ross.StoreFile("f1", []byte("Vishal"))
	ross.LoadFile("f1")
	ross.AppendFile("f1", []byte(" Chourasia"))
	ross.AppendFile("f2", []byte("IITK"))
	ross.LoadFile("f1")
	chandler.StoreFile("f2", []byte("IITKanpur"))

	// Checking Share and Recieve
	msg, err := ross.ShareFile("f1","Chandler")
	if err != nil{
                fmt.Println(err)
        }

	err = chandler.ReceiveFile("foo", "Ross Gellar", msg)
	if err != nil{
		fmt.Println("111")
		fmt.Println(err)
	}

	msg, err = chandler.ShareFile("foo","Chand")
	if err != nil{
                fmt.Println(err)
        }

	err = chand.ReceiveFile("foo1", "Chandler", msg)
	if err != nil{
		fmt.Println("111")
		fmt.Println(err)
	}

	chand.AppendFile("foo1",[]byte(" bbbbb"))
	content, err := chand.LoadFile("foo1")
    if err != nil{
            fmt.Println(err)
    }
    fmt.Println(string(content))
    
    content, err = chandler.LoadFile("foo")
    if err != nil{
            fmt.Println(err)
    }
    fmt.Println(string(content))

    content, err = ross.LoadFile("f1")
    if err != nil{
            fmt.Println(err)
    }
    fmt.Println(string(content))

	// Double share check
	err = ross.RevokeFile("f1")
        if err != nil{
                fmt.Println(err)
        }

    err = chand.ReceiveFile("foo1", "Chandler", msg)
	if err != nil{
		// fmt.Println("111")
		fmt.Println(err)
	}    

    chand.StoreFile("foo1", []byte("Upasana"))  
    content, err = chand.LoadFile("foo1")
    if err != nil{
            fmt.Println(err)
    }
    fmt.Println(string(content))
    
    content, err = chandler.LoadFile("foo")
    if err != nil{
            fmt.Println(err)
    }
    fmt.Println(string(content))

    content, err = ross.LoadFile("f1")
    if err != nil{
            fmt.Println(err)
    }
    fmt.Println(string(content))

/*	content, err := chandler.LoadFile("foo")
	if err != nil{
                fmt.Println(err)
        }
	fmt.Println(string(content))

	err = ross.RevokeFile("f1")
	if err != nil{
		fmt.Println(err)
	}

	err = ross.RevokeFile("f1")
        if err != nil{
                fmt.Println(err)
        }

	ross.AppendFile("f1", []byte(" Pagal"))

	err = chandler.ReceiveFile("foo", "Ross Gellar", msgid)
	if err != nil{
		fmt.Println("aaa")
                fmt.Println(err)
        } */
}

