"""
Name:           Tag Nabber
Version:        0.0.1
Date:           02/06/2019
Author:         SolomonSklash - solomonsklash@0xfeed.io - Penetration Tester with FIS Global
Github:         https://github.com/SolomonSklash/cookie-decrypter/
Description:    This extension identifies anchor tags and other potential sources of Tabnabbing.
Copyright (c) 2019 SolomonSklash
"""

try:
    from burp import IBurpExtender, IScannerCheck, IScanIssue
    from java.lang import RuntimeException
    from java.io import PrintWriter
    from array import array
    import re
    # Makes exceptions prettier
    from exceptions_fix import FixBurpExceptions
    import sys
except ImportError:
    print "Failed to load dependencies."

VERSION = '0.0.1'
DEBUG = 1

# Pre-compile regexes
TARGET_REGEX = r"(?i)\<\s?a\s?[^\>]*target\s?=\s?[\"|\']\s?_blank\s?[\"|\'][^\>]*\>"

try:
    COMPILED_TARGET_REGEX = re.compile(TARGET_REGEX)
except:
    print "Failed to compile regexes."

# Inherit IBurpExtender as base class, which defines registerExtenderCallbacks
# Inherit IScannerCheck to register as custom scanner

class BurpExtender(IBurpExtender, IScannerCheck):
    """ Primary Burp extension class."""
    # get references to callbacks, called when extension is loaded
    def registerExtenderCallbacks(self, callbacks):
        """Get references to callback utility functions."""
        # get a local instance of callbacks object
        self._callbacks = callbacks
        self._callbacks.setExtensionName("Tag Nabber")
        self._helpers = self._callbacks.getHelpers()

        # register as scanner object so we get used for active/passive scans
        self._callbacks.registerScannerCheck(self)

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._stdout.println("""Successfully loaded Tag Nabber """ + VERSION + """\n
Repository @ https://github.com/SolomonSklash/tag-nabber
Send feedback or bug reports to solomonsklash@0xfeed.io
Copyright (c) 2018 SolomonSklash""")
        if DEBUG:
            self._stdout.println("\n\nDEBUG enabled!")

        # Makes exceptions prettier
        sys.stdout = callbacks.getStdout()

        return

    # Get matches for highlighting locations in responses
    # https://github.com/PortSwigger/example-scanner-checks/blob/master/python/CustomScannerChecks.py
    def _get_matches(self, response, result):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(result)
        while start < reslen:
            start = self._helpers.indexOf(response, result, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        if DEBUG:
            print"DEBUG:    _get_matches() array locations"
            for match in matches:
                print "DEBUG:    " + str(match)
        return matches

    # Parse response for anchor tags
    def PARSE_REGEX_RESPONSE(self, baseRequestResponse):
        """Parse HTTP response for regex match."""
        print "In PARSE_REGEX_RESPONSE!"
        matches = []

        try:
            response = baseRequestResponse.getResponse()
        except:
            self._stderr.println("Failed to get response.")

        try:
            target_match = COMPILED_TARGET_REGEX.findall(self._helpers.bytesToString(response))
        except:
            self._stderr.println("Failed to run regexes.")

        try:
            for match in target_match:
                if DEBUG:
                    print "DEBUG:    PARSE_REGEX_RESPONSE() script regex match"
                    print "DEBUG:    " + str(match)

                if "noreferrer" not in match and "noopener" not in match:
                    print "NOT FOUND, RAISE ISSUE!!!!!!!"
                    matches.append(match)

        except:
            self._stderr.println("Failed to iterate through matches.")

        return matches

    # 'The Scanner invokes this method for each base request/response that is
    # passively scanned'
    # passing the self object as well for access to helper functions, etc.
    # java.util.List<IScanIssue> doPassiveScan(IHttpRequestResponse
    # baseRequestResponse)

    def doPassiveScan(self, baseRequestResponse):
        """Run passive scan check."""
        # Get MIME Type of response
        try:
            response = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
            mime = response.getStatedMimeType()
            if DEBUG:
                print "DEBUG:    mime type"
                print "DEBUG:    " + str(mime)
        except:
            self._stderr.println("Failed to get mime type.")

        # MIME types to check for script and link tags
        mime_types = ["HTML", "script", "text"]

        if mime not in mime_types:
            print "Exiting due to improper MIME Type"
            return None

        issues = list()

        # Parse response for <a> tags
        try:
            matches = self.PARSE_REGEX_RESPONSE(baseRequestResponse)
        except:
            self._stderr.println("Failed to get regex matches.")

        for match in matches:
            # Get offsets for highlighting response in issue detail
            try:
                offset = self._get_matches(baseRequestResponse.getResponse(), match)
            except:
                self._stderr.println("Failed to get match offset.")

            try:
                issues.append(SRIScanIssue(baseRequestResponse.getHttpService(),
                                           self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                           [self._callbacks.applyMarkers(baseRequestResponse, None, offset)]
                                          ))
            except:
                self._stderr.println("Failed to append issue.")

        if issues:
            return issues

        return None

    # 'The Scanner invokes this method when the custom Scanner check has
    # reported multiple issues for the same URL path'
    # 'The method should return -1 to report the existing issue only, 0 to
    # report both issues, and 1 to report the new issue only.'
    # consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

# 'This interface is used to retrieve details of Scanner issues. Extensions
# can obtain details of issues by registering an IScannerListener or
# by calling IBurpExtenderCallbacks.getScanIssues(). Extensions can also add
# custom Scanner issues by registering an IScannerCheck or calling
# IBurpExtenderCallbacks.addScanIssue(), and providing their own
# implementations of this interface. Note that issue descriptions and other
# text generated by extensions are subject to an HTML whitelist that allows
# only formatting tags and simple hyperlinks.'
# Here we are implementing our own custom scan issue to set scan issue
# information parameters and creating getters for each parameter


class SRIScanIssue(IScanIssue):
    """Scan issue class."""
    # constructor for setting issue information
    def __init__(self, httpService, url, requestResponse):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return 'Tabnabbing'

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return 'Information'

    def getConfidence(self):
        return 'Firm'

    def getIssueBackground(self):
        return "Tabnabbing occurs when a page opens a link using the target=\"_blank\" " \
            "attribute within an anchor HTML tag, while omitting the rel=\"noreferrer\" " \
            "or rel=\"noopener\" attributes. This method of opening a new tab or window " \
            "preserves a reference to the parent window/tab's window.opener Javascript " \
            "object, allowing the child window/tab to modify this value and change the " \
            "parent's URL while focus is on the child, thus \"nabbing\" the parent. This " \
            "method can be very effective when combined with a fake phishing site that " \
            "resembles the parent's original page. Applications allowing the embedding " \
            "of user-controlled links should be especially aware of this issue."

    def getRemediationBackground(self):
        return "https://www.owasp.org/index.php/Reverse_Tabnabbing<br>" \
               "https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/HTML5_Security_Cheat_Sheet.md#tabnabbing<br>" \
               "https://mathiasbynens.github.io/rel-noopener/<br>" \
               "https://www.netsparker.com/blog/web-security/tabnabbing-protection-bypass/"

    def getIssueDetail(self):
        description = "An anchor or link tag uses the target=\"_blank\" attribute without also " \
                      " including either the rel=\"noreferrer\" or rel=\"noopener\" attribute."
        return description

    def getRemediationDetail(self):
        return "Ensure that any anchor tags using the target=\"_blank\" attribute also include either or both of the rel=\"noreferrer\" and rel=\"noopener\" tags."

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpService

# Make exceptions prettier
FixBurpExceptions()
