// In-process native Windows OPC API adapter; no child processes.
// Signature validation checks CMS/XMLDSig integrity; eIDAS QES and package-wide
// unsigned additions require distinct independent acceptance. MIT/Apache-2.0.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <msopc.h>
#include <wincrypt.h>
#include <wrl/client.h>
#include <string>
#include <vector>
#include <cstdio>

using Microsoft::WRL::ComPtr;

namespace {
struct ComInit {
  HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  ~ComInit() { if (SUCCEEDED(hr)) CoUninitialize(); }
};
bool absolute_path(const wchar_t* p) {
  if (!p || !*p) return false;
  // C:\... or \\server\share\...; deny relative paths and drive-relative forms.
  const size_t n = wcslen(p);
  return (n >= 4 && p[1] == L':' && p[2] == L'\\') ||
         (n >= 5 && p[0] == L'\\' && p[1] == L'\\');
}
int hexval(wchar_t x) {
  if(x>=L'0'&&x<=L'9') return x-L'0';
  if(x>=L'a'&&x<=L'f') return x-L'a'+10;
  if(x>=L'A'&&x<=L'F') return x-L'A'+10;
  return -1;
}
bool parse_sha1(const wchar_t* text, BYTE out[20]) {
  if(!text || wcslen(text)!=40) return false;
  for(int i=0;i<20;++i) {
    int a=hexval(text[2*i]),b=hexval(text[2*i+1]);
    if(a<0||b<0) return false;
    out[i]=static_cast<BYTE>((a<<4)|b);
  }
  return true;
}
HRESULT make_factory(ComPtr<IOpcFactory>& factory) {
  return CoCreateInstance(__uuidof(OpcFactory),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&factory));
}
HRESULT load_package(IOpcFactory* factory,const wchar_t* path,ComPtr<IOpcPackage>& package) {
  ComPtr<IStream> stream;
  HRESULT hr=factory->CreateStreamOnFile(path,OPC_STREAM_IO_READ,nullptr,FILE_ATTRIBUTE_NORMAL,&stream);
  if(FAILED(hr)) return hr;
  return factory->ReadPackageFromStream(stream.Get(),OPC_VALIDATE_ON_LOAD,&package);
}
HRESULT append_relationships(IOpcSignatureRelationshipReferenceSet* refs, IOpcUri* source, IOpcRelationshipSet* set) {
  ComPtr<IOpcRelationshipEnumerator> en;
  HRESULT hr=set->GetEnumerator(&en);
  if(FAILED(hr)) return hr;
  ComPtr<IOpcRelationshipSelectorSet> selectors;
  hr=refs->CreateRelationshipSelectorSet(&selectors);
  if(FAILED(hr)) return hr;
  int count=0;
  BOOL more=FALSE;
  while(SUCCEEDED(hr=en->MoveNext(&more)) && more) {
    ComPtr<IOpcRelationship> item;
    hr=en->GetCurrent(&item);
    if(FAILED(hr)) return hr;
    LPWSTR id=nullptr;
    hr=item->GetId(&id);
    if(FAILED(hr)) return hr;
    ComPtr<IOpcRelationshipSelector> selector;
    hr=selectors->Create(OPC_RELATIONSHIP_SELECT_BY_ID,id,&selector);
    CoTaskMemFree(id);
    if(FAILED(hr)) return hr;
    ++count;
  }
  if(FAILED(hr)||!count) return hr;
  ComPtr<IOpcSignatureRelationshipReference> signedRelation;
  return refs->Create(source,nullptr,OPC_RELATIONSHIP_SIGN_USING_SELECTORS,
                      selectors.Get(),OPC_CANONICALIZATION_C14N,&signedRelation);
}
HRESULT sign_parts(IOpcFactory* factory,IOpcPackage* package,IOpcSigningOptions* options) {
  ComPtr<IOpcSignaturePartReferenceSet> partRefs;
  ComPtr<IOpcSignatureRelationshipReferenceSet> relRefs;
  HRESULT hr=options->GetSignaturePartReferenceSet(&partRefs);
  if(FAILED(hr)) return hr;
  hr=options->GetSignatureRelationshipReferenceSet(&relRefs);
  if(FAILED(hr)) return hr;
  ComPtr<IOpcPartSet> parts;
  hr=package->GetPartSet(&parts);
  if(FAILED(hr)) return hr;
  ComPtr<IOpcPartEnumerator> en;
  hr=parts->GetEnumerator(&en);
  if(FAILED(hr)) return hr;
  BOOL more=FALSE;
  int signedParts=0;
  while(SUCCEEDED(hr=en->MoveNext(&more)) && more) {
    ComPtr<IOpcPart> part;
    hr=en->GetCurrent(&part);
    if(FAILED(hr)) return hr;
    ComPtr<IOpcPartUri> uri;
    hr=part->GetName(&uri);
    if(FAILED(hr)) return hr;
    ComPtr<IOpcSignaturePartReference> sref;
    hr=partRefs->Create(uri.Get(),nullptr,OPC_CANONICALIZATION_NONE,&sref);
    if(FAILED(hr)) return hr;
    ++signedParts;
    ComPtr<IOpcRelationshipSet> rels;
    hr=part->GetRelationshipSet(&rels);
    if(FAILED(hr)) return hr;
    hr=append_relationships(relRefs.Get(),uri.Get(),rels.Get());
    if(FAILED(hr)) return hr;
  }
  if(FAILED(hr)) return hr;
  if(signedParts==0) return E_INVALIDARG;
  ComPtr<IOpcRelationshipSet> rootRelations;
  hr=package->GetRelationshipSet(&rootRelations);
  if(FAILED(hr)) return hr;
  ComPtr<IOpcUri> root;
  hr=factory->CreatePackageRootUri(&root);
  if(FAILED(hr)) return hr;
  return append_relationships(relRefs.Get(),root.Get(),rootRelations.Get());
}
// Require every non-signature OPC part to have an authenticated part reference.
// Windows IOpcDigitalSignatureManager::Validate verifies only the referenced
// bytes and otherwise accepts an appended unsigned part. This additional check
// deliberately fails closed rather than upgrading a partial signature to PASS.
bool signature_metadata_part(IOpcPart* part) {
  LPWSTR ct=nullptr;
  if(FAILED(part->GetContentType(&ct))) return false;
  std::wstring typ=ct?ct:L"";
  CoTaskMemFree(ct);
  ComPtr<IOpcPartUri> uri;
  if(FAILED(part->GetName(&uri))) return false;
  BSTR name=nullptr;
  if(FAILED(uri->GetPath(&name))) return false;
  std::wstring path=name?name:L"";
  SysFreeString(name);
  // Both Office signature containers and WindowsBase PackageDigitalSignatureManager
  // use these designated metadata paths. Other unsigned parts are never exempt.
  if(path.rfind(L"/_xmlsignatures/",0)!=0 &&
     path.rfind(L"/package/services/digital-signature/",0)!=0) return false;
  return typ==L"application/vnd.openxmlformats-package.digital-signature-origin"
      || typ==L"application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"
      || typ==L"application/vnd.openxmlformats-package.digital-signature-certificate";
}
HRESULT signature_metadata_allowlist(IOpcDigitalSignatureManager* manager,
                                    std::vector<ComPtr<IOpcPartUri>>& allowed) {
  ComPtr<IOpcPartUri> origin;
  HRESULT hr=manager->GetSignatureOriginPartName(&origin);
  if(FAILED(hr)) return hr;
  if(origin) allowed.push_back(origin);
  ComPtr<IOpcDigitalSignatureEnumerator> signatures;
  hr=manager->GetSignatureEnumerator(&signatures);
  if(FAILED(hr)) return hr;
  BOOL more=FALSE;
  while(SUCCEEDED(hr=signatures->MoveNext(&more))&&more) {
    ComPtr<IOpcDigitalSignature> entry;
    hr=signatures->GetCurrent(&entry);
    if(FAILED(hr)) return hr;
    ComPtr<IOpcPartUri> part;
    hr=entry->GetSignaturePartName(&part);
    if(FAILED(hr)) return hr;
    allowed.push_back(part);
    if(allowed.size()>200000) return E_INVALIDARG;
  }
  return hr;
}
HRESULT verify_part_coverage(IOpcPackage* package, IOpcDigitalSignatureManager* manager,
                             IOpcDigitalSignature* signature) {
  std::vector<ComPtr<IOpcPartUri>> approvedMetadata;
  HRESULT metaHr=signature_metadata_allowlist(manager,approvedMetadata);
  if(FAILED(metaHr)) return metaHr;

  ComPtr<IOpcSignaturePartReferenceEnumerator> refs;
  HRESULT hr=signature->GetSignaturePartReferenceEnumerator(&refs);
  if(FAILED(hr)) return hr;
  std::vector<ComPtr<IOpcPartUri>> signedUris;
  BOOL more=FALSE;
  while(SUCCEEDED(hr=refs->MoveNext(&more)) && more) {
    ComPtr<IOpcSignaturePartReference> reference;
    hr=refs->GetCurrent(&reference);
    if(FAILED(hr)) return hr;
    ComPtr<IOpcPartUri> name;
    hr=reference->GetPartName(&name);
    if(FAILED(hr)) return hr;
    signedUris.push_back(name);
    if(signedUris.size()>200000) return E_INVALIDARG;
  }
  if(FAILED(hr)||signedUris.empty()) return FAILED(hr)?hr:TRUST_E_BAD_DIGEST;
  ComPtr<IOpcPartSet> set;
  hr=package->GetPartSet(&set);
  if(FAILED(hr)) return hr;
  ComPtr<IOpcPartEnumerator> parts;
  hr=set->GetEnumerator(&parts);
  if(FAILED(hr)) return hr;
  int checked=0;
  while(SUCCEEDED(hr=parts->MoveNext(&more)) && more) {
    ComPtr<IOpcPart> part;
    hr=parts->GetCurrent(&part);
    if(FAILED(hr)) return hr;
    if(signature_metadata_part(part.Get())) {
      // Even a signature MIME type under a conventional signature folder is
      // not enough: its precise URI must be an actual OPC origin/signature
      // part reported by the verified signature manager.
      ComPtr<IOpcPartUri> metadataUri;
      hr=part->GetName(&metadataUri);
      if(FAILED(hr)) return hr;
      bool isLinked=false;
      for(const auto& trustedPart:approvedMetadata) {
        INT32 comparison=1;
        hr=metadataUri->ComparePartUri(trustedPart.Get(),&comparison);
        if(FAILED(hr)) return hr;
        if(comparison==0) {isLinked=true;break;}
      }
      if(!isLinked) return TRUST_E_BAD_DIGEST;
      continue;
    }
    ComPtr<IOpcPartUri> partUri;
    hr=part->GetName(&partUri);
    if(FAILED(hr)) return hr;
    bool authenticated=false;
    for(const auto& known:signedUris) {
      INT32 eq=1;
      hr=partUri->ComparePartUri(known.Get(),&eq);
      if(FAILED(hr)) return hr;
      if(eq==0) {authenticated=true;break;}
    }
    if(!authenticated) return TRUST_E_BAD_DIGEST;
    if(++checked>200000) return E_INVALIDARG;
  }
  return FAILED(hr)?hr:S_OK;
}
HRESULT crypto_verify(IOpcPackage* package, IOpcDigitalSignatureManager* manager, int* checked) {
  ComPtr<IOpcDigitalSignatureEnumerator> en;
  HRESULT hr=manager->GetSignatureEnumerator(&en);
  if(FAILED(hr)) return hr;
  BOOL more=FALSE;
  int valid=0;
  while(SUCCEEDED(hr=en->MoveNext(&more)) && more) {
    ComPtr<IOpcDigitalSignature> sig;
    hr=en->GetCurrent(&sig);
    if(FAILED(hr)) return hr;
    ComPtr<IOpcCertificateEnumerator> certs;
    hr=sig->GetCertificateEnumerator(&certs);
    if(FAILED(hr)) return hr;
    BOOL hasCert=FALSE;
    bool thisSigValid=false;
    while(SUCCEEDED(hr=certs->MoveNext(&hasCert)) && hasCert) {
      const CERT_CONTEXT* certificate=nullptr;
      hr=certs->GetCurrent(&certificate);
      if(FAILED(hr)) return hr;
      OPC_SIGNATURE_VALIDATION_RESULT verdict=OPC_SIGNATURE_INVALID;
      HRESULT check=manager->Validate(sig.Get(),certificate,&verdict);
      if(SUCCEEDED(check)&&verdict==OPC_SIGNATURE_VALID) thisSigValid=true;
    }
    if(FAILED(hr)) return hr;
    if(!thisSigValid) return TRUST_E_BAD_DIGEST;
    hr=verify_part_coverage(package,manager,sig.Get());
    if(FAILED(hr)) return hr;
    ++valid;
  }
  if(FAILED(hr)) return hr;
  if(valid<=0) return TRUST_E_NOSIGNATURE;
  *checked=valid;
  return S_OK;
}
} // namespace

extern "C" __declspec(dllexport) long __cdecl craft_opc_verify_inprocess(
    const wchar_t* source,int* signaturesChecked) noexcept {
  if(!absolute_path(source)||!signaturesChecked) return E_INVALIDARG;
  *signaturesChecked=0;
  ComInit com;
  if(FAILED(com.hr)&&com.hr!=RPC_E_CHANGED_MODE) return com.hr;
  ComPtr<IOpcFactory> factory;
  HRESULT hr=make_factory(factory);
  if(FAILED(hr)) return hr;
  ComPtr<IOpcPackage> pkg;
  hr=load_package(factory.Get(),source,pkg);
  if(FAILED(hr)) return hr;
  ComPtr<IOpcDigitalSignatureManager> mgr;
  hr=factory->CreateDigitalSignatureManager(pkg.Get(),&mgr);
  if(FAILED(hr)) return hr;
  return crypto_verify(pkg.Get(),mgr.Get(),signaturesChecked);
}

extern "C" __declspec(dllexport) long __cdecl craft_opc_sign_inprocess(
    const wchar_t* source,const wchar_t* destination,const wchar_t* sha1Thumbprint) noexcept {
  if(!absolute_path(source)||!absolute_path(destination)||wcscmp(source,destination)==0)
    return E_INVALIDARG;
  BYTE digest[20]={};
  if(!parse_sha1(sha1Thumbprint,digest)) return E_INVALIDARG;
  if(GetFileAttributesW(destination)!=INVALID_FILE_ATTRIBUTES) return HRESULT_FROM_WIN32(ERROR_FILE_EXISTS);
  ComInit com;
  if(FAILED(com.hr)&&com.hr!=RPC_E_CHANGED_MODE) return com.hr;
  ComPtr<IOpcFactory> factory;
  HRESULT hr=make_factory(factory);
  if(FAILED(hr)) return hr;
  ComPtr<IOpcPackage> pkg;
  hr=load_package(factory.Get(),source,pkg);
  if(FAILED(hr)) return hr;
  ComPtr<IOpcDigitalSignatureManager> manager;
  hr=factory->CreateDigitalSignatureManager(pkg.Get(),&manager);
  if(FAILED(hr)) return hr;
  ComPtr<IOpcDigitalSignatureEnumerator> existing;
  hr=manager->GetSignatureEnumerator(&existing);
  if(FAILED(hr)) return hr;
  BOOL already=FALSE;
  hr=existing->MoveNext(&already);
  if(FAILED(hr)) return hr;
  if(already) return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS); // no silent overwrite or counter-sign.
  HCERTSTORE certStore=CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_CURRENT_USER,L"MY");
  if(!certStore) return HRESULT_FROM_WIN32(GetLastError());
  CRYPT_HASH_BLOB thumbprint={20,digest};
  PCCERT_CONTEXT cert=CertFindCertificateInStore(certStore,X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
    0,CERT_FIND_SHA1_HASH,&thumbprint,nullptr);
  if(!cert) { CertCloseStore(certStore,0); return HRESULT_FROM_WIN32(ERROR_NOT_FOUND); }
  ComPtr<IOpcSigningOptions> options;
  hr=manager->CreateSigningOptions(&options);
  if(SUCCEEDED(hr)) hr=options->SetDefaultDigestMethod(L"http://www.w3.org/2001/04/xmlenc#sha256");
  if(SUCCEEDED(hr)) hr=options->SetSignatureMethod(L"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
  if(SUCCEEDED(hr)) hr=sign_parts(factory.Get(),pkg.Get(),options.Get());
  if(SUCCEEDED(hr)) {
    ComPtr<IOpcDigitalSignature> signature;
    // User's Windows crypto provider may show its normal PIN prompt here.
    hr=manager->Sign(cert,options.Get(),&signature);
  }
  CertFreeCertificateContext(cert);
  CertCloseStore(certStore,0);
  if(FAILED(hr)) return hr;
  GUID guid;
  hr=CoCreateGuid(&guid);
  if(FAILED(hr)) return hr;
  wchar_t uuid[40]={};
  StringFromGUID2(guid,uuid,40);
  std::wstring temp=std::wstring(destination)+L".tmp"+uuid;
  ComPtr<IStream> out;
  hr=factory->CreateStreamOnFile(temp.c_str(),OPC_STREAM_IO_WRITE,nullptr,FILE_ATTRIBUTE_NORMAL,&out);
  if(SUCCEEDED(hr)) hr=factory->WritePackageToStream(pkg.Get(),OPC_WRITE_DEFAULT,out.Get());
  out.Reset();
  if(SUCCEEDED(hr)) {
    int valid=0;
    // The result is reopened independently, not only verified in memory.
    long check=craft_opc_verify_inprocess(temp.c_str(),&valid);
    if(FAILED(check)||valid!=1) {
      hr=FAILED(check)?check:TRUST_E_BAD_DIGEST;
    }
  }
  if(SUCCEEDED(hr)&&!MoveFileExW(temp.c_str(),destination,MOVEFILE_WRITE_THROUGH))
    hr=HRESULT_FROM_WIN32(GetLastError());
  if(FAILED(hr)) DeleteFileW(temp.c_str());
  return hr;
}
