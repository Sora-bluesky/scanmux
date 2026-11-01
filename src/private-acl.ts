export const administratorsSid = 'S-1-5-32-544';

// An elevated administrator token makes BUILTIN\Administrators the default owner of every new file, so a
// store written under it is owned by that group rather than the user. The group is accepted only while the
// token is elevated; IsInRole is false for a filtered token, whose Administrators entry is deny-only.
export const privateAclRule = `
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$sid=$identity.User
$elevated=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function Test-PrivateOwner($owner, $user, $elevatedToken) {
  return $null -ne $owner -and ($owner.Value -eq $user.Value -or ($elevatedToken -and $owner.Value -eq '${administratorsSid}'))
}
function Test-PrivateAcl($security, $user, $elevatedToken, $requireProtected) {
  if (!(Test-PrivateOwner ($security.GetOwner([Security.Principal.SecurityIdentifier])) $user $elevatedToken)) { return $false }
  if ($requireProtected -and !$security.AreAccessRulesProtected) { return $false }
  $rules=@($security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  return $rules.Count -eq 1 -and $rules[0].IdentityReference.Value -eq $user.Value -and $rules[0].AccessControlType -eq 'Allow' -and $rules[0].FileSystemRights -eq 'FullControl'
}
`;
