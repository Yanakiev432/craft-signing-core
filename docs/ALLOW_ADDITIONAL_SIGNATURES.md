# Additional signatures in Craft applications (Windows)

The default signing choice is **Allow additional signatures** (enabled).
Its interface label and help text are in English in PdfCraft, WordCraft and
GridCraft. The signing certificate is chosen explicitly from Windows
Current User / Personal. The provider owns key use and PIN input.

## PdfCraft — PDF

A standard PDF approval signature does not itself impose a DocMDP
certification lock. The UI therefore displays the additional-signatures
option as enabled, but fixed, for standard approval signatures.

For a PDF certification signature, the option is editable: enabled means
DocMDP permission P=2 (form fill and further signatures), or P=3 when
annotations are already allowed; disabled sets P=1 (no subsequent changes).
Changing existing signed bytes can invalidate earlier signatures regardless
of the permission setting. The final PDF requires independent validation.

## WordCraft / GridCraft — DOCX / XLSX

The Windows OPC/XMLDSig implementation signs the saved document using the
selected Windows certificate. A later signer can reopen the **existing signed
copy** and add a separate signature without replacing or invalidating the
first. The signer rejects invalid earlier signatures and separately protects
each content part and each non-signature OPC relationship.

The two mutable signature-container relationship parts are intentionally
excluded as raw byte-range inputs. The remaining document relationships
are protected by explicit OPC relationship selectors, and verification
rejects unprotected additions. This preserves the first signature when
the next signer is appended to the signature container.

The implementation has synthetic independent-certificate tests for both
DOCX and XLSX, verifying two signatures, invalid content rejection,
unsigned part rejection and unsigned relationship rejection.

If **Allow additional signatures** is unchecked for the FIRST signature,
Craft includes a signed internal `/craft/signature-policy.xml` part and
refuses further signing through the Craft signing adapter. This policy is
specific to Craft. It is **not** a standardized read-only protection or
document lock recognized by all Microsoft Office applications; other
programs may ignore it. It cannot be added retroactively after a prior
signature without invalidating the original signed bytes.

The drawn screen rectangle currently selects a visible location in the
application workflow; it is **not yet a native Word/Excel signature-line
shape stored in the OOXML document**. Do not claim appearance interoperability
with Microsoft Word/Excel until a native OOXML signature-line object and
real Office acceptance tests pass.

Cryptographic integrity PASS is not eIDAS/QES qualification. Actual B-Trust
hardware token signing, trust lists, revocation and qualified timestamping
are separate tests. Never export private keys or enter PINs in Craft.
