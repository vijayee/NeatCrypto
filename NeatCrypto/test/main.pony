use ".."
use "ponytest"
use "collections"
use "time"
use @printf[I32](fmt: Pointer[U8] tag, ...)

actor Main is TestList
  new create(env: Env) =>
    PonyTest(env, this)
  new make () =>
    None
  fun tag tests(test: PonyTest) =>
    test(_TestBlake3)


class iso _TestBlake3 is UnitTest
    fun name(): String => "Testing Cert Creation"
    fun apply(t: TestHelper) =>
      try
        let key: Key[RSA] val = Key[RSA](4096)?
        try
          let cert: X509 = X509(None)?
          try
            cert.setKey(key)?
            let subjectName: Name = Name
            try
              subjectName.commonName = "Test Certificate"
              subjectName.country = "US"
              subjectName.state = "DC"
              subjectName.organization = "Testify"
              subjectName.organizationalUnit = "Test Org"
              subjectName.email = "test@test.com"
              subjectName.locality = "North America"
              cert.setSubjectName(subjectName)?
              try
                cert.setIssuerName(subjectName)?
                try
                  cert.setSerialNumber(146)?
                  try
                    cert.setVersion(1)?
                    try
                      match Time.now()
                        | (let seconds: I64, let nanoseconds: I64) =>
                          cert.setNotBefore(seconds.u64())?
                      end
                      try
                        match Time.now()
                          | (let seconds: I64, let nanoseconds: I64) =>
                            cert.setNotAfter(seconds.u64())?
                        end
                        try
                          key.signX509(cert)?
                          try
                            let pem: String = cert.toPEM()?
                            t.log(pem)
                            try
                              let pem2: String = key.toPrivateKeyPEM()?
                              t.log(pem2)
                              try
                                let pem3: String = key.toPublicKeyPEM()?
                                t.log(pem3)
                              else
                                t.fail("Error creating Public Key PEM encoded string")
                                t.complete(true)
                              end
                            else
                              t.fail("Error creating Private Key PEM encoded string")
                              t.complete(true)
                            end
                          else
                            t.fail("Error creating  cert PEM encoded string")
                            t.complete(true)
                          end
                        else
                          t.fail("Failed to sign certifcate")
                          t.complete(true)
                        end
                      else
                        t.fail("Error setting not after")
                        t.complete(true)
                      end
                    else
                      t.fail("Error setting not before")
                      t.complete(true)
                    end
                  else
                    t.fail("Error setting issuer name")
                    t.complete(true)
                  end
                else
                  t.fail("Error setting serial number")
                  t.complete(true)
                end
              else
                t.fail("Error setting issuer name")
                t.complete(true)
              end
            else
              t.fail("Error setting subject name")
              t.complete(true)
            end
          else
            t.fail("Error Setting Key")
            t.complete(true)
          end
        else
          t.fail("Error Creating Certificate")
          t.complete(true)
        end
      else
        t.fail("Error Creating Key")
        t.complete(true)
      end
