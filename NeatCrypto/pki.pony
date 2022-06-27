use "lib:neat"

use @pony_alloc[Pointer[U8]](ctx: Pointer[None], size: USize)
use @pony_ctx[Pointer[None]]()
use @create_rsa_keys[Pointer[None]](bits: U32)?
use @create_x509[Pointer[None]]()?
use @remove_keys[None](key: Pointer[None] tag)
use @remove_x509[None](x: Pointer[None] tag)
use @x509_set_pubkey[None](x: Pointer[None] tag, key: Pointer[None] tag)?
use @x509_set_subject_name[None](x: Pointer[None] tag, name: Pointer[None] tag)?
use @x509_set_serial_number[None](x: Pointer[None] tag, number: I64)?
use @x509_set_version[None](x: Pointer[None] tag, version: I64)?
use @x509_set_notBefore[None](x: Pointer[None] tag, time: U64)?
use @x509_set_notAfter[None](x: Pointer[None] tag, time: U64)?
use @x509_create_name[Pointer[None] tag]()?
use @x509_remove_name[None](n: Pointer[None] tag)
use @x509_set_name_country[None](n: Pointer[None] tag, country: Pointer[U8] tag)?
use @x509_set_name_state[None](n: Pointer[None] tag, state: Pointer[U8] tag)?
use @x509_set_name_common_name[None](n: Pointer[None] tag, commonName: Pointer[U8] tag)?
use @x509_set_name_organization[None](n: Pointer[None] tag, organization: Pointer[U8] tag)?
use @x509_set_name_organizational_unit[None](n: Pointer[None] tag,  ou: Pointer[U8] tag)?
use @x509_set_name_locality[None](n: Pointer[None] tag, locality: Pointer[U8] tag)?
use @x509_set_issuer_name[None](x: Pointer[None], name: Pointer[None] tag)?
use @x509_write_PEM[BufMemStr](x: Pointer[None], bp: Pointer[None])?
use @create_bio[Pointer[None]]()?
use @remove_bio[None](bp: Pointer[None] tag)
use @sign_x509[None](x: Pointer[None] tag, key: Pointer[None] tag)?
use @write_privateKey_PEM[BufMemStr](bp: Pointer[None] tag, key: Pointer[None] tag)?
use @write_pubKey_PEM[BufMemStr](bp: Pointer[None] tag, key: Pointer[None] tag)?


primitive RSA

type KeyAlgorithm is (RSA)

class val Key[A: KeyAlgorithm = RSA]
  let evp_key: Pointer[None] tag
  new val create(bits: U32)? =>
    iftype A <: RSA then
      evp_key = @create_rsa_keys(bits)?
    else
      error
    end
  fun signX509(x509: X509) ? =>
    @sign_x509(x509.x509, evp_key)?

  fun toPrivateKeyPEM(): String ? =>
    let bp: Pointer[None] = @create_bio()?
    let buf: BufMemStr = @write_privateKey_PEM(bp, evp_key)?
    let pemRaw: String ref = String.from_cpointer(buf.data, buf.length)
    let pem: String iso = recover String(pemRaw.size()) end
    for i in pemRaw.values() do
      pem.push(i)
    end
    @remove_bio(bp)
    consume pem

  fun toPublicKeyPEM(): String ? =>
    let bp: Pointer[None] = @create_bio()?
    let buf: BufMemStr = @write_pubKey_PEM(bp, evp_key)?
    let pemRaw: String ref = String.from_cpointer(buf.data, buf.length)
    let pem: String iso = recover String(pemRaw.size()) end
    for i in pemRaw.values() do
      pem.push(i)
    end
    @remove_bio(bp)
    consume pem

  fun _final() =>
    @remove_keys(evp_key)


class Name
  var commonName: (String | None) = None
  var country: (String | None) = None
  var state: (String | None) = None
  var organization: (String | None) = None
  var organizationalUnit: (String | None) = None
  var email: (String | None) = None
  var locality: (String | None) = None

struct BufMemStr
  var length: USize = 0
  var data: Pointer[U8] = @pony_alloc(@pony_ctx(), 0)
  var max: USize = 0
  var flags: U64 = 0

class X509
  let x509: Pointer[None] tag
  new create(stuff: None)? =>
    x509 = @create_x509()?

  fun ref setSubjectName(name: Name)? =>
    let n: Pointer[None] tag = @x509_create_name()?
    try
      match name.commonName
        | let commonName: String =>
          @x509_set_name_common_name(n, commonName.cstring())?
      end
      match name.country
        | let country: String =>
          @x509_set_name_country(n, country.cstring())?
      end
      match name.state
        | let state: String =>
          @x509_set_name_state(n, state.cstring())?
      end
      match name.organization
        | let organization: String =>
          @x509_set_name_organization(n, organization.cstring())?
      end
      match name.organizationalUnit
        | let organizationalUnit: String =>
          @x509_set_name_organizational_unit(n, organizationalUnit.cstring())?
      end
      match name.locality
        | let locality: String =>
          @x509_set_name_locality(n, locality.cstring())?
      end
      @x509_set_subject_name(x509, n)?
    else
      @x509_remove_name(n)
      error
    end

  fun ref setIssuerName(name: Name)? =>
    let n: Pointer[None] tag = @x509_create_name()?
    try
      match name.commonName
        | let commonName: String =>
          @x509_set_name_common_name(n, commonName.cstring())?
      end
      match name.country
        | let country: String =>
          @x509_set_name_country(n, country.cstring())?
      end
      match name.state
        | let state: String =>
          @x509_set_name_state(n, state.cstring())?
      end
      match name.organization
        | let organization: String =>
          @x509_set_name_organization(n, organization.cstring())?
      end
      match name.organizationalUnit
        | let organizationalUnit: String =>
          @x509_set_name_organizational_unit(n, organizationalUnit.cstring())?
      end
      match name.locality
        | let locality: String =>
          @x509_set_name_locality(n, locality.cstring())?
      end
      @x509_set_issuer_name(x509, n)?
    else
      @x509_remove_name(n)
      error
    end

  fun ref setKey(key: Key[KeyAlgorithm])? =>
    @x509_set_pubkey(x509, key.evp_key)?

  fun ref setSerialNumber(number: I64)? =>
    @x509_set_serial_number(x509, number)?

  fun ref setVersion(version: I64)? =>
    @x509_set_version(x509, version)?

  fun ref setNotBefore(time: U64)? =>
    @x509_set_notBefore(x509, time)?

  fun ref setNotAfter(time: U64)? =>
    @x509_set_notAfter(x509, time)?

  fun toPEM(): String ? =>
    let bp: Pointer[None] = @create_bio()?
    let buf: BufMemStr = @x509_write_PEM(x509, bp)?
    let pemRaw: String ref = String.from_cpointer(buf.data, buf.length)
    let pem: String iso = recover String(pemRaw.size()) end
    for i in pemRaw.values() do
      pem.push(i)
    end
    @remove_bio(bp)
    consume pem

  fun _final() =>
    @remove_x509(x509)
