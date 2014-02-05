#!/usr/bin/ksh

echo "Creating package..."
# clean up directories of previous builds
rm -rf .info
rm -rf tmp
# create the file tree
mkdir -p opt/CertNanny/bin
mkdir -p opt/CertNanny/inst
mkdir -p usr/bin
cp COPYRIGHT opt/CertNanny/COPYRIGHT.sscep
cp sscep_static opt/CertNanny/bin
cp sscep_dyn opt/CertNanny/bin
cp AIX/sscep.pre-install.sh opt/CertNanny/inst
cp AIX/sscep.pre-deinstall.sh opt/CertNanny/inst
# compute the version number (VRML)
version=$(head -n 1 VERSION)
version="$version.0"
# create the template and building the package
sed "s/VERSIONINFO/$version/" < AIX/lpp_template.in | sed "s#__PACKAGINGDIR__#$PWD#" > AIX/lpp_template
mkinstallp -d . -T AIX/lpp_template

