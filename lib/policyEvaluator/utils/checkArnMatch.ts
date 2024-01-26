import { handleWildcardInResource } from './wildcards';

/**
 * Checks whether an ARN from a request matches an ARN in a policy
 * to compare against each portion of the ARN from the request
 * @param policyArn - arn from policy
 * @param requestRelativeId - last part of the arn from the request
 * @param requestArnArr - all parts of request arn split on ":"
 * @param caseSensitive - whether the comparison should be
 * case sensitive
 * @return true if match, false if not
 */
export default function checkArnMatch(
    policyArn: string,
    requestRelativeId: string,
    requestArnArr: string[],
    caseSensitive: boolean,
): boolean {
    const regExofArn = handleWildcardInResource(policyArn);
    // The relativeId is the last part of the ARN (for instance, a bucket and
    // object name in S3)
    // Join on ":" in case there were ":" in the relativeID at the end
    // of the arn
    const policyRelativeId = caseSensitive ? regExofArn.slice(5).join(':') :
        regExofArn.slice(5).join(':').toLowerCase();
    const policyRelativeIdRegEx = new RegExp(policyRelativeId);
    // Check to see if the relative-id matches first since most likely
    // to diverge.  If not a match, the resource is not applicable so return
    // false
    if (!policyRelativeIdRegEx.test(caseSensitive ?
        requestRelativeId : requestRelativeId.toLowerCase())) {
        return false;
    }
    // Check the other parts of the ARN to make sure they match.  If not,
    // return false.
    for (let j = 0; j < 5; j++) {
        const segmentRegEx = new RegExp(regExofArn[j]);
        const requestSegment = caseSensitive ? requestArnArr[j] :
            requestArnArr[j].toLowerCase();
        const policyArnArr = policyArn.split(':');
        // We want to allow an empty account ID for utapi and scuba service ARNs to not
        // break compatibility.
        const allowedEmptyAccountId = ['utapi', 'scuba'];
        if (j === 4 && allowedEmptyAccountId.includes(policyArnArr[2]) && policyArnArr[4] === '') {
            continue;
        } else if (!segmentRegEx.test(requestSegment)) {
            return false;
        }
    }
    // If there were matches on all parts of the ARN, return true
    return true;
}
