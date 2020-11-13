#!/bin/bash -e
#
# (c) 2013 Canonical Inc.,
# Chris J Arges <chris.j.arges@canonical.com>
#
# A script create a hotfix changes file for uploading to a PPA.
#

SHOW_WARNING=""

# hosts where nobody should have private keys
NO_SIGN_HOSTS="rotom"

BUILDNO=1
ESCALATION=0
LP=0
ISSUE=""
DEBDIR="debian.master"
KEY=""
SIGN=1
FORCE_SIGN=0 # param overrides NO_SIGN_HOSTS
BUILD_BINARY=0
CLEAN=1
CLEAN_BRANCH=0
MV_OUTPUT=0
COMMITID=0
HASH=""
HF_OR_TEST=0
SKIP_BUILDDEP=0

function is_true { [[ $1 =~ 1|y|yes|Y|YES|true|TRUE ]]; }

function exit_help
{
    echo "Usage: $0 -i <NUM> -e <NUM> [options]"
    echo ""
    echo "	-i NUM		description of the issue (required)"
    echo "	-e NUM		salesforce escalation number (required)"
    echo "	-l NUM		public launchpad bug number"
    echo "	-d DIR		debian directory name [debian.master]"
    echo "	-b NUM		build number version suffix [1]"
    echo "	-k KEY		key to use for signing"
    echo "	-s 0|1		sign output [true]"
    echo "	-B 0|1		build binary debs also [false]"
    echo "	-m 0|1		mv output into ~/hfEEEEEvDATEbB/ [false]"
    echo "	-n 0|1		clean up after building [true]"
    echo "	-N 0|1		(requires -n 1) remove the created hf* branch [false]"
    echo "	-H 0|1		add the commit ID to the postfix [false]"
    echo "	-T 0|1		instead of hfxxx, use TESTxxx as kernel version [false]"
    echo "	-D 0|1		skip build-time dependency checks by dpkg-buildpackage [false]"
    exit $1
}

# Parse options
while getopts "e:l:i:b:d:k:m:n:N:s:B:H:T:D:h" opt; do
    case $opt in
        e) ESCALATION=$OPTARG ;;
        l) LP=$OPTARG ;;
        i) ISSUE=$OPTARG ;;
        b) BUILDNO=$OPTARG ;;
        d) DEBDIR=$OPTARG ;;
        k) KEY=$OPTARG ;;
        m) MV_OUTPUT=$OPTARG ;;
        n) CLEAN=$OPTARG ;;
        N) CLEAN_BRANCH=$OPTARG ;;
        s) SIGN=$OPTARG ; FORCE_SIGN=$OPTARG ;;
        B) BUILD_BINARY=$OPTARG ;;
	H) COMMITID=$OPTARG ;;
        T) HF_OR_TEST=$OPTARG ;;
        D) SKIP_BUILDDEP=$OPTARG ;;
        h) exit_help 0 ;;
        *) exit_help 1 ;;
    esac
done

# Find required abi-disable script
ABI_DISABLE=$( which abi-disable ) || ABI_DISABLE=$( dirname $0 )/abi-disable
if ! [[ -x $ABI_DISABLE ]] ; then
    echo "Couldn't find required helper program 'abi-disable'"
    exit 1
fi

# Enforce required parameters
if [ $ESCALATION == 0 ]; then
    echo "Enter an escalation number using (-e)."
    exit 1
fi
if [[ $ISSUE == "" ]]; then
    echo "Enter an issue description using (-i)."
    exit 1
fi

# Almost certainly should set DEBEMAIL to get changelog email right
if [[ -z $DEBFULLNAME ]] ; then
    export DEBFULLNAME="$( git config --get user.name | head -1 )"
    if [[ -z $DEBFULLNAME ]] ; then
        echo "Warning: DEBFULLNAME and git user.name unset, you may want to set one."
        unset DEBFULLNAME
        SHOW_WARNING=true
    else
        echo "Notice: DEBFULLNAME not set, using $DEBFULLNAME"
    fi
fi
if [[ -z $DEBEMAIL ]] ; then
    export DEBEMAIL="$( git config --get user.email | head -1 )"
    if [[ -z $DEBEMAIL ]] ; then
        echo "Warning: DEBEMAIL and git user.email unset, you may want to set one."
        unset DEBEMAIL
        SHOW_WARNING=true
    else
        echo "Notice: DEBEMAIL not set, using $DEBEMAIL"
    fi
fi

# Check if we shouldn't sign on this host
if is_true $SIGN ; then
    for h in $NO_SIGN_HOSTS ; do
        if [[ $( hostname ) == $h ]] ; then
            if is_true $FORCE_SIGN ; then
                echo "Notice: detected host $h, but signing enabled by parameter."
            else
                echo "Notice: detected host $h, disabling signing."
                SIGN=0
            fi
        fi
    done
fi

# Verify key exists
if [[ -n ${KEY} ]] ; then
    if gpg --list-keys ${KEY} > /dev/null ; then
        KEY="-k${KEY}"
    else
        echo "ERROR: No GPG key ${KEY} found."
        exit 1
    fi
else
    if is_true $SIGN && [[ -z $( gpg --list-keys ) ]] ; then
        echo "Warning: no GPG keys found, to skip signing use -s 0"
        SHOW_WARNING=true
    fi
fi

[[ $SHOW_WARNING == "true" ]] && sleep 5

################################################################################

# Check if we're in a git directory
git rev-parse || exit
#if [ `git rev-parse` ]; then
#    echo "Needs to be run from within a git repository."
#    exit
#fi

# For sure there's a smarter way to grep this - if you improve it, coffee on me next sprint!
if [[ `git rev-parse --abbrev-ref HEAD | grep '[0-9]*v[0-9]*b[0-9]*' | grep 'hf\|TEST'` ]] ; then
    echo "ERROR: You are currently on a git TEST/hf* branch, this is probably not what you want"
    exit 1
fi


# Clean before everything
git clean -x -f -d
git reset --hard HEAD
fakeroot debian/rules clean

NAME=`git config -l | grep user.name | head -1 | cut -d'=' -f 2`
DATE=`date +%Y%0m%0d`
NAME_BASE=`dpkg-parsechangelog | grep Source | cut -d' ' -f2`
SERIES=`dpkg-parsechangelog | grep Distribution | cut -d' ' -f2`
ORIG_VERSION=`dpkg-parsechangelog | grep Version | cut -d' ' -f2`

# prefix kernel version with hf or TEST, depending on -T flag
if is_true ${HF_OR_TEST}; then
	HF_OR_TEST="TEST"
	HF_OR_TEST_MSG="TEST kernel for"
else
	HF_OR_TEST="hf"
	HF_OR_TEST_MSG="HOTFIX kernel for"
fi

POSTFIX=${HF_OR_TEST}${ESCALATION}v${DATE}b${BUILDNO}

# add the commit id
if is_true $COMMITID ; then
    HASH=$(git show --oneline HEAD | head -n1 | awk '{print $1}')
    POSTFIX=${POSTFIX}h${HASH}
fi

FULL_VERSION=${ORIG_VERSION}+${POSTFIX}
FILE_BASE=${NAME_BASE}_${FULL_VERSION}
OUTPUT_DIR=".."
is_true $MV_OUTPUT && OUTPUT_DIR="$HOME/$POSTFIX"
MESSAGE="[ ${NAME} ]\\
\\
  * ${HF_OR_TEST_MSG}: ${ISSUE}\\
    - ESCALATION: #${ESCALATION}"
MESSAGE_LP="\\
    - LP: #${LP}"
if [ $LP != 0 ]; then
    MESSAGE=${MESSAGE}${MESSAGE_LP}
fi


# Verify the branch we are going to create doesn't exist
if git rev-parse --verify "$POSTFIX" 1> /dev/null 2> /dev/null ; then
    echo "ERROR: branch $POSTFIX already exists, you must delete it first."
    exit 1
fi

# Create the output dir if needed
if [[ ! -d $OUTPUT_DIR ]] ; then
    if ! mkdir -p $OUTPUT_DIR ; then
        echo "ERROR: Could not create output dir $OUTPUT_DIR"
        exit 1
    fi
fi

# Get current git branch if needed, to checkout back to after cleaning
if is_true $CLEAN ; then
    if ! GIT_INITIAL_BRANCH="$( git symbolic-ref --short -q HEAD )" ; then
        # detached HEAD, let's find the tag or commit
        if ! GIT_INITIAL_BRANCH="$( git status -b | sed -rne '1s/^HEAD detached at (.*)/\1/p' )" ; then
            echo "Warning: can't determine your current detached head tag, using commit id."
            GIT_INITIAL_BRANCH="$( git rev-parse HEAD )"
        fi
    fi
fi

# Setup output dir and build dir, so output files in ".." are in clean dir
if is_true $MV_OUTPUT ; then
    HOTFIX_ORIG_DIR=$( pwd )
    HOTFIX_ORIG_PHYS=$( pwd -P )
    HOTFIX_PHYS_DIR=$( dirname "$HOTFIX_ORIG_PHYS" )
    HOTFIX_PHYS_BASE=$( basename "$HOTFIX_ORIG_PHYS" )
    if [[ $( stat -f -c '%i' "$HOTFIX_ORIG_PHYS" ) != \
	  $( stat -f -c '%i' "$HOTFIX_PHYS_DIR" ) ]] ; then
	echo "$HOTFIX_PHYS_DIR and $HOTFIX_ORIG_PHYS are different filesystems,"
	echo "so I can't move the output, sorry"
	exit 1
    fi
    HOTFIX_OUTPUT_DIR=$HOTFIX_PHYS_DIR/.hotfix-output-dir
    if [[ -e $HOTFIX_OUTPUT_DIR ]] ; then
	echo "$HOTFIX_OUTPUT_DIR already exists,"
	echo "please remove it"
	exit 1
    fi
    mkdir "$HOTFIX_OUTPUT_DIR"
    HOTFIX_NEW_PHYS="$HOTFIX_OUTPUT_DIR/$HOTFIX_PHYS_BASE"
    mv "$HOTFIX_ORIG_PHYS" "$HOTFIX_NEW_PHYS"
    ln -s "$HOTFIX_NEW_PHYS" "$HOTFIX_ORIG_PHYS"
    cd "$HOTFIX_NEW_PHYS"
fi

function success_msg
{
    # User may need to sign the package
    if ! is_true $SIGN ; then
	echo ""
	echo "################################################################################"
	echo "You need to sign your package.  You can use debsign locally:"
	echo "[local]$ debsign ${OUTPUT_DIR}/${FILE_BASE}_source.changes"
	echo "or you can use debsign remotely:"
	[[ $OUTPUT_DIR == ".." ]] && FILE_DIR="$( cd .. ; pwd )/" || FILE_DIR="$OUTPUT_DIR/"
	FILE_DIR="${FILE_DIR#$HOME/}"
	echo "[remote]$ debsign -r $( hostname ):${FILE_DIR}${FILE_BASE}_source.changes"
    fi

    # Upload to the PPA builder (make user do this manually)
    echo ""
    echo "################################################################################"
    echo "Double check your changes. When you are ready to upload use the following:"
    echo "dput ppa:canonical-support-eng/sf${ESCALATION} ${OUTPUT_DIR}/${FILE_BASE}_source.changes"
}

function do_on_exit
{
    echo
    if [ $SUCCESS = 1 ] ; then
	echo "Build successful, cleaning up."
    else
	echo "Build FAILED, cleaning up."
    fi
    echo

    # Clean up
    if is_true $CLEAN ; then
	git clean -x -f -d
	git reset --hard HEAD
	git checkout "$GIT_INITIAL_BRANCH"
	if is_true $CLEAN_BRANCH ; then
	    [[ -n $( git branch --list $POSTFIX ) ]] && git branch -D "$POSTFIX"
	    [[ -n $( git tag --list $TAG ) ]] && git tag -d $TAG
	fi
    fi

    # mv files to output dir
    if is_true $MV_OUTPUT ; then
	rm "$HOTFIX_ORIG_PHYS" # it's a temp symlink during build
	mv "$HOTFIX_NEW_PHYS" "$HOTFIX_ORIG_PHYS"
	cd "$HOTFIX_OUTPUT_DIR"
	mv * "$OUTPUT_DIR" ||:
	cd "$HOTFIX_ORIG_DIR"
	rmdir "$HOTFIX_OUTPUT_DIR"
    fi

    [ $SUCCESS = 1 ] && success_msg
}

trap do_on_exit EXIT

SUCCESS=0

# Setup git branch
git checkout -b $POSTFIX

# Create changelog ( if you can do it without sed you win a beer )
dch -v ${FULL_VERSION} -D $SERIES  -c ${DEBDIR}/changelog "XYZZY"
sed -i 's/* XYZZY/'"${MESSAGE}"'/' ${DEBDIR}/changelog

# Disable abi checks
(
export DEBDIR
$ABI_DISABLE -f
)

# Commit to git
#git add ${DEBDIR}/abi/*/*
#git add ${DEBDIR}/changelog
git add -A
git commit -s -m "UBUNTU: ${HF_OR_TEST_MSG}: #${ESCALATION}"

# Tag commit
TAG="Ubuntu-${FULL_VERSION//\~/\-}"
git tag -d $TAG ||:
git tag $TAG

# Generate debian sources
git clean -x -f -d
fakeroot debian/rules clean
is_true $SIGN && NOSIGN="" || NOSIGN="-uc -us"
is_true $BUILD_BINARY && SRCONLY="" || SRCONLY="-S"
is_true ${SKIP_BUILDDEP} && NOCHECKDEP="-d" || NOCHECKDEP=""

DPKGBLDCMD="dpkg-buildpackage ${NOSIGN} ${KEY} ${SRCONLY} ${NOCHECKDEP} -rfakeroot -I.git -I.gitignore -i'\.git.*'"
echo "Build starting (command used: ${DPKGBLDCMD})"
eval ${DPKGBLDCMD}

SUCCESS=1
