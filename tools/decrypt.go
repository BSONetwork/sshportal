package main

import (
  "flag"
  "os"
  "log"
  crypto "moul.io/sshportal/pkg/crypto"
)

func usage(cmd string) {
  os.Stderr.WriteString("Usage: " + cmd + " < file_to_decrypt\n")
}

func main() {
  fs := flag.NewFlagSet("decrypt", flag.ExitOnError)

	useV1 := fs.Bool("legacy", false, "Decrypt a legacy stream")
  key := fs.String("key", "", "AES Key to decrypt with")

  if err := fs.Parse(os.Args[1:]); err != nil {
    log.Fatalln("Failed to parse args", err)
  }

  keyBytes := []byte(*key)

  if len(keyBytes) != 8 && len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
    os.Stderr.WriteString("Invalid key size\n")
    usage(os.Args[0])
    return
  }
  if *useV1 {
    sd := crypto.NewStreamEncrypter(os.Stdout, keyBytes)
    out, err := sd.Decrypt(os.Stdin)
    if err != nil {
      log.Fatalln("Failed to parse args", err)
    }
    os.Stdout.Write(out)
  } else {
    crypto.DecryptStreamV2(os.Stdout, keyBytes)
  }
}