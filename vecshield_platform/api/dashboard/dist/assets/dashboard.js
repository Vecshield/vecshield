const API = "";
const root = document.getElementById("root");
const state = {
  token: sessionStorage.getItem("vecshield_token") || "",
  stores: [],
  schemas: {},
  templates: [],
  policies: [],
  policiesError: "",
  admin: null,
  // The separation-of-duties policy from /version, once read.
  approvals: undefined,
  // The criterion pack, once any Compliance screen has fetched it. It is
  // versioned content, not live state, so one read per session is enough.
  pack: null,
  // What /auth/session said. Until it answers, the console behaves as it did
  // before sign-in existed: a token deployment, or an open one.
  auth: {login_enabled: false, authenticated: false, user: null, password_policy: {min_length: 12}},
  // "signin" or "password" while a full-page account screen replaces the
  // console; null while the console itself is showing.
  authScreen: null,
};

async function loadPack() {
  if (!state.pack) state.pack = await api("/compliance/criteria");
  return state.pack;
}

const severityOrder = ["critical", "high", "medium", "low", "info"];
const connectorFields = {
  chroma: [["path", "Persistent path"], ["host", "Host"], ["port", "Port", "number"]],
  pgvector: [["dsn", "DSN"], ["host", "Host"], ["port", "Port", "number"], ["dbname", "Database"], ["user", "User"], ["password_env", "Password env var"], ["retrieval_role", "Retrieval role"]],
  qdrant: [["url", "URL"], ["host", "Host"], ["port", "Port", "number"], ["api_key_env", "API key env var"]],
  weaviate: [["url", "Cloud URL"], ["host", "Host"], ["port", "HTTP port", "number"], ["grpc_port", "gRPC port", "number"], ["api_key_env", "API key env var"]],
  milvus: [["uri", "URI"], ["host", "Host"], ["port", "Port", "number"], ["token_env", "Token env var"], ["db_name", "Database"]],
  pinecone: [["api_key_env", "API key env var"]],
  redis: [["url", "URL"], ["host", "Host"], ["port", "Port", "number"], ["db", "DB", "number"], ["password_env", "Password env var"]],
  opensearch: [["url", "URL"], ["host", "Host"], ["port", "Port", "number"], ["user", "User"], ["password_env", "Password env var"]],
  mongodb: [["uri", "Connection URI"]],
  openai: [["api_key_env", "OpenAI API key env var"]],
  azure_search: [["endpoint", "Search endpoint"], ["api_key_env", "API key env var"]],
  bedrock_kb: [["region", "AWS region"], ["aws_access_key_id", "Access key ID"], ["aws_secret_access_key_env", "Secret key env var"]],
  vertex_ai: [["project", "GCP project"], ["location", "Region"], ["endpoint_id", "Endpoint ID"], ["credentials_json", "Credentials JSON path"]],
};

const svgTags = new Set(["svg", "path", "circle", "line", "polyline", "polygon", "rect",
                         "g", "text", "title", "defs", "pattern", "tspan"]);

// ============================================================ compliance copy ===
// Every word the Compliance screens show about a state, a term, or a next
// step lives here, keyed, so it can be reviewed, linted
// (tests/copy-lint.test.mjs) and one day translated. Two rules hold for all of
// it: no raw identifiers in readable text, and nothing that reads as a verdict
// that you meet the law. Primary copy is short plain English; legal detail sits
// one disclosure away and names its source.
//
// Sentences are whole templates with {placeholders}; counts use
// Intl.PluralRules through countText(), never "criterion(s)" or `${verb}d`.

const PLURAL_RULES = new Intl.PluralRules("en");

// A count with its noun from a {one, other} pair, e.g. "3 criteria".
function countText(count, forms) {
  const n = Number(count || 0);
  const form = forms[PLURAL_RULES.select(n)] ?? forms.other;
  return fillCopy(form, {n: number(n)});
}

// "{name} did it" with {name: "Dana"}. A missing value leaves an empty slot,
// never the placeholder itself.
function fillCopy(template, vars = {}) {
  return String(template ?? "").replace(/\{(\w+)\}/g, (_, key) => String(vars[key] ?? ""));
}

// A key the tables do not name, made readable rather than printed raw.
function humanize(key) {
  const text = String(key ?? "").replace(/_/g, " ").replace(/\s+/g, " ").trim();
  return text ? text[0].toUpperCase() + text.slice(1) : "";
}

// One entry of a label table: {tone, text, help, glyph}. Unknown keys get a
// readable text and the unknown tone, so a new server state is never dropped
// and never printed as an identifier.
function complianceLabel(group, key) {
  const meta = (COMPLIANCE_COPY.labels[group] || {})[key];
  if (meta) return meta;
  return {tone: "unknown", text: humanize(key) || "Unknown", help: ""};
}

// The chip for a labelled state. Tone, icon and words come from the table.
function complianceChip(group, key, {prefix = ""} = {}) {
  const meta = complianceLabel(group, key);
  return stateChip(meta.tone, prefix ? fillCopy(prefix, {state: meta.text}) : meta.text,
                   {glyph: meta.glyph || "", title: meta.help || ""});
}

const COMPLIANCE_COPY = {
  // Screen descriptions under each page title.
  views: {
    policies: "Rules that decide which findings need action, in which stores, and what to do",
    templates: "Ready-made rules by framework: read one, test it on recent findings, then turn it into a policy",
    frameworks: "Each law or standard the pack maps, and what each obligation needs from a vector store",
    criteria: "See where one store stands on each obligation, and what is still needed",
    evidence: "Add documents, then see which criteria each one was accepted or rejected for",
    exceptions: "Gaps accepted for a set time, who approved them, and when they end",
    dsar: "Find everything stored about one person, then delete it when you are ready",
  },

  labels: {
    criterionStatus: {
      not_assessed: {tone: "unknown", text: "Not assessed",
        help: "We can't say yet whether this applies, so it is neither met nor missed."},
      evidence_needed: {tone: "medium", text: "Documents needed",
        help: "It applies, but a document it needs is missing or was rejected."},
      under_review: {tone: "low", text: "Waiting for a reviewer",
        help: "Everything is in. A named reviewer needs to decide."},
      // D-C1: a reviewer's "met" is neutral, never green, and carries a check
      // mark and the word "reviewer" so it cannot pass for a scan result.
      satisfied_for_scope: {tone: "info", glyph: "check", text: "Met for this store (reviewer)",
        help: "A named reviewer decided it is met for this store and period."},
      gap_identified: {tone: "critical", text: "Gap found",
        help: "A check failed, or a reviewer recorded a gap."},
      not_applicable: {tone: "info", glyph: "sev-na", text: "Does not apply (reviewer)",
        help: "A reviewer recorded that it does not apply to this store."},
    },
    technicalResult: {
      passed: {tone: "ok", text: "Checks passed",
        help: "What the automatic checks saw. It is not a legal conclusion."},
      failed: {tone: "critical", text: "Checks failed", help: "An automatic check saw a problem."},
      inconclusive: {tone: "medium", text: "Inconclusive", help: "The checks ran but could not tell."},
      not_run: {tone: "unknown", text: "Not run", help: "No check ran for this in the saved assessment."},
    },
    technicalCoverage: {
      complete: {tone: "ok", text: "Complete"},
      partial: {tone: "medium", text: "Partial"},
      unknown: {tone: "unknown", text: "Unknown"},
      not_observable: {tone: "info", text: "Not observable"},
      does_not_arise: {tone: "info", text: "Does not come up"},
      not_applicable: {tone: "info", text: "Documents only"},
    },
    evidenceStatus: {
      not_required: {tone: "info", text: "Not needed",
        help: "No document is needed while the checks show this."},
      missing: {tone: "medium", text: "Missing",
        help: "A document it needs has not been accepted by a reviewer yet."},
      submitted: {tone: "low", text: "Waiting for review",
        help: "A document was sent for review and is waiting for a reviewer."},
      accepted: {tone: "ok", text: "Accepted", help: "A reviewer accepted every document it needs."},
      rejected: {tone: "critical", text: "Rejected",
        help: "A reviewer rejected a document. Add one that meets the need."},
    },
    requirementState: {
      accepted: {tone: "ok", text: "Accepted"},
      submitted: {tone: "low", text: "Waiting for review"},
      missing: {tone: "medium", text: "Missing"},
      rejected: {tone: "critical", text: "Rejected"},
    },
    // One map for the Exceptions table and the criterion detail, so a state
    // has one tone everywhere (they used to disagree about expired).
    exceptionStatus: {
      pending_approval: {tone: "low", text: "Waiting for approval", chip: "Exception waiting for approval",
        help: "Not in force until someone approves it."},
      active: {tone: "medium", text: "Active", chip: "Exception active",
        help: "The gap is accepted for now. It is still a gap."},
      expired: {tone: "high", text: "Expired", chip: "Exception expired",
        help: "It has ended, so the gap it covered is open again."},
      revoked: {tone: "info", text: "Revoked", chip: "Exception revoked",
        help: "It was withdrawn, so the gap it covered is open again."},
    },
    artifactState: {
      collected: {tone: "medium", text: "Added, not yet checked"},
      integrity_checked: {tone: "medium", text: "Integrity confirmed"},
      available: {tone: "ok", text: "Ready for review"},
      quarantined: {tone: "medium", text: "On hold"},
      superseded: {tone: "medium", text: "Replaced by a newer version"},
      expired: {tone: "medium", text: "Expired"},
      revoked: {tone: "critical", text: "Withdrawn"},
    },
    artifactMove: {
      integrity_checked: {text: "Confirm integrity",
        help: "You compared the file's SHA-256 with the recorded hash and they match."},
      available: {text: "Make ready for review", help: "The file is ready to be judged against criteria."},
      quarantined: {text: "Put on hold", help: "Hold it back while something about the file is checked."},
      superseded: {text: "Mark as replaced",
        help: "A newer version replaces it. Adding the new version with “Replaces” does this for you."},
      expired: {text: "Mark expired", help: "It is past its validity."},
      revoked: {text: "Withdraw", help: "Withdraw it for good. This cannot be undone."},
    },
    reviewState: {
      requested: {tone: "unknown", text: "Requested"},
      submitted: {tone: "low", text: "Waiting for review"},
      under_review: {tone: "low", text: "Under review"},
      accepted: {tone: "ok", text: "Accepted"},
      rejected: {tone: "critical", text: "Rejected"},
      needs_clarification: {tone: "medium", text: "More information needed"},
    },
    reviewMove: {
      accepted: {text: "Accept: it meets this need"},
      rejected: {text: "Reject: it does not"},
      needs_clarification: {text: "Ask for more information"},
      under_review: {text: "Reopen for review"},
      submitted: {text: "Send for review again"},
    },
    applicabilityStatus: {
      confirmed: {tone: "info", text: "Applies", help: "You answered yes to every question it asks."},
      requires_confirmation: {tone: "unknown", text: "Not sure yet",
        help: "Some of its questions are not answered. Unanswered is not “no”."},
      excluded: {tone: "info", text: "Excluded by an answer",
        help: "You answered no. A reviewer needs to confirm it before it counts."},
    },
    applicabilityAnswer: {
      yes: {tone: "info", text: "Yes"},
      no: {tone: "info", text: "No"},
      requires_confirmation: {tone: "unknown", text: "Not sure yet"},
    },
    conclusion: {
      satisfied: {tone: "info", glyph: "check", text: "Met for this store",
        help: "You checked what is here and it meets this obligation for this store and period."},
      gap: {tone: "critical", text: "Not met: there is a gap",
        help: "Something it needs is missing or failed. The gap stays open until it is fixed or an exception covers it."},
      not_applicable: {tone: "info", glyph: "sev-na", text: "Does not apply here",
        help: "This obligation does not cover this store, for example because it holds no data of that kind."},
    },
    determination: {
      accepted: {tone: "ok", text: "Accepted"},
      submitted: {tone: "low", text: "Waiting for review"},
      missing: {tone: "medium", text: "Missing"},
      rejected: {tone: "critical", text: "Rejected"},
    },
    specification: {
      required: {tone: "info", text: "Required"},
      addressable: {tone: "info", text: "Addressable"},
      standard: {tone: "info", text: "Standard"},
      risk_based: {tone: "info", text: "Risk-based"},
      implementation_specification: {tone: "info", text: "Implementation specification"},
    },
    outcome: {
      passed: {tone: "ok", text: "Passed"},
      failed: {tone: "critical", text: "Failed"},
      inconclusive: {tone: "medium", text: "Inconclusive"},
      not_run: {tone: "unknown", text: "Not run"},
      skipped: {tone: "unknown", text: "Skipped"},
      unsupported: {tone: "info", text: "Not supported"},
      error: {tone: "critical", text: "Error"},
    },
    notApplied: {
      made_against_later_audit: {text: "It was made against a later assessment."},
      criterion_changed: {text: "The criterion's wording changed after it was made."},
      digest_mismatch: {text: "The criterion's wording changed after it was made."},
    },
    // D-C8-adjacent wording for where a mapping sits (§4B.4).
    lifecycle: {
      draft: {text: "Draft mapping"},
      technically_validated: {text: "Checked by engineers"},
      regulatory_reviewed: {text: "Reviewed by a lawyer"},
      pilot: {text: "In pilot"},
      published: {text: "Published mapping"},
      superseded: {text: "Replaced by a newer mapping"},
    },
    legalStatus: {
      in_force: {text: "In force"},
      future_effective: {text: "Not yet in force"},
      proposed: {text: "Proposed, not law yet"},
      vacated_or_enjoined: {text: "Blocked or set aside by a court"},
      superseded: {text: "Replaced by newer law"},
      guidance: {text: "Guidance, not law"},
      internal: {text: "Internal policy"},
      unresolved: {text: "Source not confirmed"},
    },
    sourceKind: {
      regulation: {text: "Regulation"}, rule: {text: "Rule"}, statute: {text: "Statute"},
      contractual_standard: {text: "Contractual standard"}, internal_policy: {text: "Internal policy"},
      guidance: {text: "Guidance"},
    },
  },

  mapping: {
    notReviewed: "not reviewed by a lawyer",
    reviewedBy: "Reviewed by {name}, {date}",
    reviewedByUndated: "Reviewed by {name}",
    reviewMissing: "marked reviewed, but no review record was supplied",
    source: "source: {source}",
    pack: "pack {version}",
    hint: "A reviewed mapping describes what we check. It does not mean your store meets the law.",
    overdue: "review overdue",
  },

  plainLegal: {
    heading: "What this means for you",
    legal: "Legal wording and source",
    noWording: "The pack has no legal wording for this criterion.",
  },

  criteria: {
    explainLede: "Each criterion is judged on four things. We never merge them into one answer:",
    steps: [
      ["applies", "Your answers to its questions."],
      ["check", "What the checks saw in this store's latest saved assessment."],
      ["evidenceStatus", "Documents you add, each accepted or rejected by a reviewer."],
      ["decision", "A named person's conclusion. Only this marks a criterion as met."],
    ],
    explainFoot: "VecShield never says you meet the law. “Met for this store (reviewer)” means one named person decided it for this store and period.",
    noStore: "Showing what each criterion asks. Choose a store to see where it stands, using that store's latest saved assessment.",
    loading: "Reading this store's latest saved assessment",
    noAudit: "No saved assessment for this store.",
    noAuditDetail: "Criteria use a saved assessment of this store. Run an assessment first.",
    evaluatedAgainst: "Using assessment {audit}.",
    chooseStore: "Choose a store above to see where this criterion stands for it.",
    storeTip: "We use this store's latest saved assessment. Nothing new is scanned.",
    steps2: [
      "Choose a store. We use its latest saved assessment; nothing new is scanned.",
      "Open a criterion to see what it asks and what would meet it",
      "Answer its questions, add documents, then record a named reviewer's decision",
    ],
    nextStep: {
      noStore: "Choose a store to see where it stands",
      excluded: "Your answers say this doesn't apply. A reviewer needs to confirm it.",
      answer: {one: "Answer {n} question", other: "Answer {n} questions"},
      replaceRejected: "Replace rejected: {names}",
      supply: "Add: {names}",
      more: "{names} and {n} more",
      underReview: "Waiting for a reviewer's decision",
      exceptionActive: "Gap accepted for now; the exception ends {when}",
      failed: "Fix the failed check, or request an exception",
      reviewerGap: "A reviewer recorded a gap",
      satisfied: "Met for this store, decided by {who}",
      notApplicable: "Does not apply, decided by {who}",
      someone: "a reviewer",
    },
    fields: {applies: "Applies?", check: "Check result", evidence: "Evidence status", reviewer: "Reviewer's decision"},
    unanswered: {one: "{n} question not answered", other: "{n} questions not answered"},
    settled: "All answered",
    alwaysApplies: "Always applies",
    notAccepted: {one: "{n} document not yet accepted", other: "{n} documents not yet accepted"},
    nothingOutstanding: "Nothing outstanding",
    noDecision: "No decision recorded",
    notAppliedChip: "Not applied",
    notAppliedNote: "{who}'s decision does not apply to this assessment",
    previewOnly: "preview only, not saved",
    recorded: "{who} recorded “{conclusion}”",
    recordedWhen: "{who} recorded “{conclusion}” {when}",
    notAppliedLine: "Not applied: {why} Record a new decision if it still holds.",
    why: "Why: {text}",
    carried: "Carried forward from an earlier assessment; it still applies.",
    previewIgnored: "A preview decision sent with this view was ignored, because a saved decision exists.",
    exceptionLine: {
      active: "Accepted for now; it ends {when}. The gap is still open.",
      expired: "Ended {when}. The gap it covered is open again.",
      pending_approval: "Requested. It needs a second person's approval.",
      revoked: "Withdrawn. The gap it covered is open again.",
    },
    exceptionReason: " Reason given: {text}",
    fallbackRequired: "Needed because the store does not show this: {names}.",
    documentsHeading: "Documents that would meet it",
    judgedHeading: "How it is judged",
    observedSummary: "What the assessment saw ({n})",
    limitsSummary: "Limits of these checks",
    nothingRequired: "No document is needed: the automatic checks cover this criterion.",
    nothingYet: "Nothing is needed yet. Backup documents are asked for only when the checks can't show this.",
    conditional: "conditional",
    staleAcceptance: "An acceptance exists, but its document can no longer be used (replaced, expired or withdrawn), so it does not count.",
    strayChip: "Does not count",
    stray: "Filed under a need this criterion does not have, so it counts toward nothing here, whatever its decision.",
    specNotAsked: "Applies only if",
    specNoQuestions: "No questions: it always applies",
    specObserved: "Checked automatically",
    specNothing: "Nothing: documents only",
    specDecided: "Decided by",
    specDecidedBy: "A named reviewer",
    specDecidedHow: "Records met, gap, or does not apply, with a reason. A failed check stays a gap.",
    answerAll: "Answer this store's questions",
    packLine: "{count} · pack {version}",
  },

  technicalNote: {
    not_observable: "The store can't show this",
    does_not_arise: "This doesn't come up for this store; documents decide it",
    not_applicable: "No automatic check covers this; documents do",
    unsupported: "Not supported by {db}",
    coverage: "Coverage: {state}",
  },

  // The four inline forms that replaced the criterion dialogs (C-4).
  forms: {
    cancel: "Cancel",
    decision: {
      open: "Record decision", openAgain: "Record a new decision",
      heading: "Record a decision",
      intro: [
        "You are the reviewer. The decision is saved under your name and written to the audit log.",
        "It applies to {audit}.",
        "It never overrides a failed check. A failed check stays a gap.",
      ],
      latestAudit: "this store's latest saved assessment",
      thisAudit: "assessment {audit}",
      conclusion: "Your decision",
      rationale: "Reason (required)",
      rationaleHint: "Say why, in words another reviewer can check.",
      period: "Period (optional)",
      periodHint: "For example 2026-Q3.",
      submit: "Save decision",
      needConclusion: "Choose a decision.",
      needRationale: "Add a reason. A decision without one cannot be checked.",
      saved: "Decision saved for {who}.",
    },
    answers: {
      open: {one: "Answer {n} question", other: "Answer {n} questions"},
      heading: "Does this criterion apply?",
      intro: "Your answers are saved for {store} under your name. Each answer applies to every criterion that asks the same question. Not sure yet is not “no”.",
      who: "Answered “{answer}” by {who} {when}",
      nobody: "Not answered for this store yet",
      readFailed: "The saved answers could not be read: {why}",
      submit: "Save answers",
      saved: "Answers saved for {store}.",
      needStore: "Choose a store first; answers are saved per store.",
    },
    attach: {
      open: {one: "Add document ({n})", other: "Add documents ({n})"},
      heading: "Add a document for review",
      intro: "This sends one document for review against one need. A reviewer then accepts or rejects it on the Evidence screen.",
      need: "Document needed",
      conditional: "{name} (only because the store can't show this)",
      reviewerChecks: "A reviewer will check: {text}",
      example: "For example: {text}.",
      source: "Which document",
      existing: "One already added",
      fresh: "A new one",
      document: "Document",
      choose: "Choose a document",
      noneUsable: "No document is ready for review yet",
      loading: "Loading documents…",
      readFailed: "Documents could not be read: {why}",
      period: "Period (optional)",
      periodHint: "The period the reviewer should judge it for, such as 2026-Q3.",
      title: "Title",
      titleHint: "Name it so a reviewer knows what it is, such as “Signed BAA with Acme Vector Cloud, 2026”.",
      hash: "Content hash (SHA-256)",
      hashHint: "The file stays in your storage. The hash lets anyone confirm later it is the same file.",
      from: "Covers from",
      to: "Covers until",
      submit: "Send for review",
      needDocument: "Choose a document.",
      needTitle: "Give the document a title a reviewer will recognise.",
      badHash: "A SHA-256 hash is 64 characters, 0–9 and a–f, optionally starting sha256:.",
      badPeriod: "The end of the period is before its start.",
      sent: "Document sent for review.",
      sentNew: "Document added and sent for review. It counts only after its integrity is confirmed and it is made ready for review on the Evidence screen.",
      openEvidence: "Open it on the Evidence screen",
    },
    approve: {
      open: "Approve",
      heading: "Approve this exception",
      reason: "Why you approve it (required)",
      reasonHint: "Recorded with your name in the audit log.",
      submit: "Approve exception",
      needReason: "Say why you approve it. An approval without a reason cannot be checked.",
      done: "Exception approved.",
      revoked: "Exception revoked.",
    },
  },

  questionnaire: {
    heading: "Questions for {store}",
    lede: "Answer each question once. Your answer applies to every criterion that asks it.",
    scope: "{questions} cover {criteria}.",
    questions: {one: "{n} question", other: "{n} questions"},
    criteria: {one: "{n} criterion", other: "{n} criteria"},
    affects: {one: "Why we ask · affects {n} criterion", other: "Why we ask · affects {n} criteria"},
    options: {yes: "Yes", no: "No", requires_confirmation: "Not sure yet"},
    progress: "{answered} of {total} answered",
    savedAt: "{progress} · saved {when}",
    save: "Save answers",
    saved: "Answers saved.",
    nothingChanged: "Nothing changed, so nothing was saved.",
    readOnly: "You can read these answers. Changing them needs the compliance role.",
    back: "Back to criteria",
    open: "Answer this store's questions",
    none: "No criterion in this pack asks a question.",
    noStore: "Choose a store: answers are saved per store.",
    readFailed: "The saved answers could not be read.",
  },

  exceptions: {
    header: "Gaps someone decided to accept for now, and until when.",
    pending: "Waiting for approval", pendingNote: "not in force yet",
    active: "Active", activeNote: "accepted for now; still a gap",
    lapse: {one: "{n} ends within 30 days", other: "{n} end within 30 days"},
    expired: "Expired", expiredNote: "the gap is open again",
    steps: [
      "Someone requests one for a criterion in one store, with a reason and an end date",
      "{approver} Until then it is not in force",
      "It ends or is revoked, and the gap it covered is open again",
    ],
    columns: ["Criterion", "Store", "Status", "Ends", "Reason requested", ""],
    requestedBy: "requested by {who}",
    approvedBy: "approved by {who}",
    approvalReason: "Approval reason: “{text}”",
    noApprovalReason: "No approval reason recorded",
    empty: "No exceptions have been requested.",
    revokeTitle: "Revoke this exception?",
    revokeMessage: "{criterion} in {scope} stops being accepted now, and the gap it covered is open again. A revoked exception can't be brought back; you would need to request a new one.",
    revokeConfirm: "Revoke exception",
    requestNote: "An exception records that you accept a gap for now. It does not close the gap, and it ends on a set date.",
  },

  exportCaveats: [
    "This pack has not been reviewed by a lawyer.",
    "Status counts describe this assessment and its documents. They are not a score and do not add up across frameworks.",
    "An exception accepts a gap for now. It does not close the gap.",
    "Only a named reviewer can mark a criterion as met for this store.",
  ],

  frameworks: {
    header: "Which obligations this pack maps, and what stands behind each one.",
    barLede: "Each card is one law or standard the pack maps. The bar shows how much VecShield can check automatically and how much needs your documents.",
    barAuto: {one: "{n} checked automatically", other: "{n} checked automatically"},
    barManual: {one: "{n} needs your documents", other: "{n} need your documents"},
  },

  dsar: {
    header: "Find everything stored about one person, check it, then delete it when you are ready.",
    purpose: "Requests about one person's data. A request first searches your stores, read-only, for everything that mentions them. Deleting it is a separate step you choose afterwards.",
    stepErase: "Only when you choose to: matched chunks are deleted, then checked three ways to confirm they are gone.",
    readOnly: "Read-only so far: nothing has been deleted. Review the {matches}, then delete them when you are ready.",
    erase: "Delete this person's data",
    retry: "Retry deleting this person's data",
    erased: "Data deleted; verification recorded.",
    failed: "Deletion did not run",
    blocker: "You opened this request, so another compliance user must delete its data.",
    newRequest: "Opening a request searches read-only. Nothing is deleted until you choose to from the request's page.",
    erasedWhen: "deleted",
  },

  policies: {
    header: "Policies decide which findings need action, and in which stores.",
  },
};

// Plain-language glossary (§4B.2). Each term is defined once, here. It is
// shown through <dfn> the first time a screen uses it, and in full on Docs.
const COMPLIANCE_TERMS = {
  framework: ["Framework", "A law or standard, such as GDPR or SOC 2."],
  obligation: ["Obligation", "Something a framework requires of you."],
  criterion: ["Criterion", "One obligation, restated as what we can look for in a vector store."],
  control: ["Control", "Something your organisation does to meet an obligation."],
  template: ["Template", "A ready-made detection rule tied to a framework. It does nothing until it becomes a policy."],
  policy: ["Policy", "A rule switched on for your stores. It turns matching findings into items you must act on."],
  applies: ["Applies?", "Whether an obligation covers this store, based on your answers. Unanswered is not “no”."],
  check: ["Check result", "What VecShield's automatic checks saw. Never a legal conclusion."],
  evidenceStatus: ["Evidence status", "Whether the documents a criterion needs have been accepted by a reviewer."],
  decision: ["Reviewer's decision", "A named person's conclusion, with a reason. Only this marks a criterion as met for a store."],
  document: ["Document", "A file you keep, added here by title, period and fingerprint."],
  exception: ["Exception", "An approved, time-limited decision to live with a gap. The gap stays open."],
  suppression: ["Suppression", "Silencing one known-harmless finding until a date. It is not about obligations."],
};

if (typeof window !== "undefined") {
  window.COMPLIANCE_COPY = COMPLIANCE_COPY;
  window.COMPLIANCE_TERMS = COMPLIANCE_TERMS;
}

// Terms already defined on the screen being drawn. route() clears it, so each
// screen defines a term once, at its first use.
let definedTerms = new Set();

// The term as a <dfn> the first time this screen uses it, plain text after.
// The definition rides in the title and is read out through the describing
// span, so it is not a hover-only secret.
function termUse(key, text = "") {
  const [label, definition] = COMPLIANCE_TERMS[key] || [key, ""];
  const shown = text || label;
  if (definedTerms.has(key) || !definition) return h("span", {class: "term"}, shown);
  definedTerms.add(key);
  return h("dfn", {class: "term", title: definition, dataset: {term: key}}, shown);
}

// A compact list of terms with their definitions, each a <dfn> on its first
// use: the "About this screen" glossary and the Docs page use it.
function termList(keys) {
  return h("dl", {class: "term-list"}, keys.filter(k => COMPLIANCE_TERMS[k]).flatMap(key => [
    h("dt", {}, termUse(key)),
    h("dd", {}, COMPLIANCE_TERMS[key][1]),
  ]));
}

// Six task areas, each owning the screens that belong to one job. The screens
// themselves are unchanged: this re-parents them, it does not rewrite them, so
// nothing can be lost in the move. `views` stays the flat registry every
// renderer and deep link resolves through; `AREAS` is how it is presented.
const views = {
  overview: ["Overview", "Compliance and security posture across your vector stores", "Overview", renderOverview],
  stores: ["Stores", "Registered vector databases and managed connectors", "Estate", renderStores],
  schema: ["Schema", "Collections, vector counts, and metadata field counts", "Estate", renderSchemaExplorer],
  crypto: ["Crypto", "Encryption and data protection a saved audit observed, layer by layer", "Estate", renderCrypto],
  assess: ["New assessment", "Run assessments against registered stores", "Assessments", renderAssess],
  history: ["History", "Recorded scans, audits, and posture checks", "Assessments", renderHistory],
  jobs: ["Runs", "Queued and completed long-running workflows", "Assessments", renderJobs],
  findings: ["Findings", "Observations across recorded assessments", "Findings", renderFindings],
  actions: ["Actions", "What could be done about a finding, and what was refused", "Findings", renderActions],
  policies: ["Policies", COMPLIANCE_COPY.views.policies, "Compliance", renderPolicies],
  templates: ["Templates", COMPLIANCE_COPY.views.templates, "Compliance", renderTemplates],
  falsepositives: ["False positives", "Allow-list rules and time-boxed suppressions that tag known-benign matches without hiding them", "Findings", renderFalsePositives],
  frameworks: ["Frameworks", COMPLIANCE_COPY.views.frameworks, "Compliance", renderFrameworks],
  criteria: ["Criteria", COMPLIANCE_COPY.views.criteria, "Compliance", renderCriteria],
  evidence: ["Evidence", COMPLIANCE_COPY.views.evidence, "Compliance", renderEvidence],
  exceptions: ["Exceptions", COMPLIANCE_COPY.views.exceptions, "Compliance", renderExceptions],
  runtime: ["Runtime", "Live query-monitor alerts and test-event ingestion", "Operations", renderRuntime],
  detectors: ["Detectors", "Configure alerts for unusual query activity", "Operations", renderDetectors],
  alerting: ["Alerting", "Delivery sinks for audit and runtime alerts", "System", renderAlerting],
  ingest: ["Ingest", "Try sensitive-content checks before embedding", "Operations", renderIngest],
  // D-C8: the tab reads "Personal data requests"; the id stays `dsar`, so
  // every link and bookmark still resolves.
  dsar: ["Personal data requests", COMPLIANCE_COPY.views.dsar, "Compliance", renderDSAR],
  audit: ["Audit log", "Tamper-evident console and API activity", "System", renderAudit],
  status: ["Status", "Readiness, versions, and runtime configuration", "System", renderStatus],
  users: ["Users", "Who can sign in, and what each person may do", "System", renderUsers],
  settings: ["Settings", "Your profile, password and sessions, and this browser's preferences", "Account", renderSettings],
  docs: ["Docs", "What the console does, what each screen answers, and what it refuses to claim", "Docs", renderDocs],
};

// The fifth field says where an area lives: the main navigation, the small
// "System" group at the foot of the sidebar, the help icon in the top bar, or
// the account menu (personal Settings, never a workspace screen).
// Consolidated 2026-09-24 (docs/console_ux_roadmap.md, Batch 3): view ids and
// deep links are unchanged, only where the screens are presented moved.
const AREAS = [
  ["Overview", "grid", "What changed, what needs you, and what was never measured", ["overview"], "main"],
  ["Estate", "db", "What you have, and how much of it can be inspected", ["stores", "schema", "crypto"], "main"],
  ["Assessments", "shield", "What you ran, what is running, and what it established", ["assess", "history", "jobs"], "main"],
  ["Findings", "alert", "What is wrong, where, how confident the detector is, and what is known to be benign",
   ["findings", "actions", "falsepositives"], "main"],
  ["Compliance", "layers", "Which rules apply, what they establish, and who decided",
   ["criteria", "frameworks", "evidence", "exceptions", "dsar", "policies", "templates"], "main"],
  ["Operations", "sliders", "Runtime monitoring, detector thresholds, and ingest checks",
   ["runtime", "detectors", "ingest"], "main"],
  ["System", "list", "Delivery, activity, readiness, and who can sign in to this deployment",
   ["audit", "alerting", "status", "users"], "system"],
  ["Docs", "file", "What the console does, and what each screen answers", ["docs"], "help"],
  ["Account", "user", "Who you are signed in as, your sessions, and this browser's preferences", ["settings"], "account"],
];

// Screens shown as a view inside another screen rather than as a tab of their
// own: Frameworks within Criteria, Templates within Policies, Runs within
// History. Each keeps its id and its links; the parent's tab stays current.
// History and Runs share one in-page switch (historySwitch) instead of the
// chrome's, so the reader sees one row of choices, not two stacked.
const SUBVIEW_PARENT = {frameworks: "criteria", templates: "policies", jobs: "history"};

function subviewsOf(parent) {
  return Object.entries(SUBVIEW_PARENT).filter(([, p]) => p === parent).map(([id]) => id);
}

function areaOf(viewId) {
  return AREAS.find(([, , , members]) => members.includes(viewId));
}

function areaHome(areaName) {
  const area = AREAS.find(([name]) => name === areaName);
  return area ? area[3][0] : "overview";
}


function h(tag, attrs = {}, ...children) {
  const isSvg = svgTags.has(tag);
  const node = isSvg
    ? document.createElementNS("http://www.w3.org/2000/svg", tag)
    : document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === false || value == null) continue;
    if (key === "class" && isSvg) node.setAttribute("class", String(value));
    else if (key === "class") node.className = value;
    else if (key === "ariaLabel") node.setAttribute("aria-label", String(value));
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else if (key === "checked" || key === "selected" || key === "disabled") node[key] = Boolean(value);
    else node.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function icon(name) {
  const paths = {
    grid: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    db: "M4 6c0-2 16-2 16 0v12c0 2-16 2-16 0V6zm0 6c0 2 16 2 16 0M4 6c0 2 16 2 16 0",
    shield: "M12 3l8 3v5c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10V6z",
    funnel: "M4 5h16l-6 7v6l-4 2v-8z",
    sliders: "M5 7h14M5 17h14M8 4v6M16 14v6",
    layers: "M12 3l9 5-9 5-9-5zm-7 9l7 4 7-4M5 16l7 4 7-4",
    alert: "M12 3l10 18H2zm0 6v5m0 3h.01",
    bell: "M18 8a6 6 0 10-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M9.5 20a3 3 0 005 0",
    user: "M20 21a8 8 0 10-16 0M12 11a4 4 0 100-8 4 4 0 000 8",
    users: "M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2M9 11a4 4 0 100-8 4 4 0 000 8zM22 21v-2a4 4 0 00-3-3.9M16 3.1a4 4 0 010 7.8",
    list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
    clock: "M12 22a10 10 0 110-20 10 10 0 010 20zm0-14v5l3 2",
    plus: "M12 5v14M5 12h14",
    play: "M8 5v14l11-7z",
    refresh: "M21 12a9 9 0 11-3-6.7M21 3v6h-6",
    trash: "M3 6h18M8 6V4h8v2m-10 0l1 15h10l1-15",
    copy: "M8 8h11v13H8zM5 16H4a1 1 0 01-1-1V4a1 1 0 011-1h11a1 1 0 011 1v1",
    moon: "M21 12.8A9 9 0 1111.2 3 7 7 0 0021 12.8z",
    sun: "M12 4V2m0 20v-2m8-8h2M2 12h2m13.7-7.7l1.4-1.4M4.9 19.1l1.4-1.4m0-11.4L4.9 4.9m14.2 14.2l-1.4-1.4M12 17a5 5 0 100-10 5 5 0 000 10",
    menu: "M4 6h16M4 12h16M4 18h16",
    more: "M5 13a1 1 0 100-2 1 1 0 000 2zm7 0a1 1 0 100-2 1 1 0 000 2zm7 0a1 1 0 100-2 1 1 0 000 2z",
    help: "M12 22a10 10 0 110-20 10 10 0 010 20zM9.1 9a3 3 0 015.8 1c0 2-3 3-3 3m.1 4h.01",
    close: "M6 6l12 12M18 6L6 18",
    back: "M19 12H5m6-6l-6 6 6 6",
    search: "M21 21l-4.3-4.3M10.5 18a7.5 7.5 0 110-15 7.5 7.5 0 010 15",
    archive: "M3 5h18v4H3zM5 9h14v10H5zM10 13h4",
    code: "M16 18l6-6-6-6M8 6l-6 6 6 6",
    file: "M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8zM14 2v6h6",
    hash: "M10 3L8 21M16 3l-2 18M4 9h17M3 15h17",
    key: "M21 2l-2 2m-7.6 7.6a5 5 0 11-7-7 5 5 0 017 7zM12 12l8-8",
    tag: "M20 12l-8 8-8-8V4h8zM7.5 7.5h.01",
    check: "M20 6L9 17l-5-5",
    info: "M12 22a10 10 0 110-20 10 10 0 010 20zm0-6v-4m0-4h.01",
    edit: "M12 20h9M16.5 3.5a2.1 2.1 0 113 3L7 19l-4 1 1-4z",
    "sev-critical": "M12 22a10 10 0 110-20 10 10 0 010 20zM15 9l-6 6M9 9l6 6",
    "sev-high": "M12 3l10 18H2zm0 6v5m0 3h.01",
    "sev-medium": "M12 22a10 10 0 110-20 10 10 0 010 20zM12 8v5m0 3h.01",
    "sev-low": "M12 22a10 10 0 110-20 10 10 0 010 20zM12 8v8m-3-3l3 3 3-3",
    "sev-info": "M12 22a10 10 0 110-20 10 10 0 010 20zm0-6v-4m0-4h.01",
    "sev-ok": "M12 22a10 10 0 110-20 10 10 0 010 20zM8 12l3 3 5-6",
    "sev-unknown": "M12 22a10 10 0 110-20 10 10 0 010 20zM9.6 9.4a2.5 2.5 0 014.9.6c0 1.6-2.5 2-2.5 3.5M12 17h.01",
    lock: "M5 11h14v10H5zM8 11V7a4 4 0 118 0v4",
    "eye-off": "M3 3l18 18M10.6 5.1A10 10 0 0112 5c6.5 0 10 7 10 7a17 17 0 01-3.2 4M6.6 6.6C3.8 8.5 2 12 2 12s3.5 7 10 7a9.7 9.7 0 005.4-1.6M9.9 9.9a3 3 0 004.2 4.2",
    "sev-na": "M12 22a10 10 0 110-20 10 10 0 010 20zM8 12h8",
    "sev-notrun": "M12 22a10 10 0 110-20 10 10 0 010 20zM5 5l14 14",
    eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zm10 3a3 3 0 100-6 3 3 0 000 6",
    "chevron-right": "M9 6l6 6-6 6",
  };
  return h("svg", {class: "icon", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true"},
    h("path", {d: paths[name] || paths.grid}));
}

// The account endpoints answer their own 401s (a wrong password, a wrong
// current password); only a 401 from anything else means the session ended.
const AUTH_PATHS = /^\/auth\/(session|login|logout|password)(\?|$)/;
const PASSWORD_CHANGE_REQUIRED = "password change required";

async function api(path, opts = {}) {
  // Every request says it came from the console: a cookie-authenticated
  // unsafe request without this header is refused by the server (CSRF).
  const headers = {"Accept": "application/json", "X-VecShield-CSRF": "1", ...(opts.headers || {})};
  if (opts.body && !(opts.body instanceof FormData)) headers["Content-Type"] = "application/json";
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  let response;
  try {
    response = await fetch(API + path, {credentials: "same-origin", ...opts, headers});
  } catch {
    setHealth("err", "Unreachable");
    throw new Error("The VecShield API is unreachable.");
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const data = await response.json();
      detail = describeDetail(data.detail) || detail;
    } catch { /* a non-JSON error body leaves the status text */ }
    if (response.status === 401) setHealth("warn", "Authentication required");
    const err = new Error(detail);
    err.status = response.status;
    // What the server said, as distinct from the status text standing in for it.
    err.detail = detail !== response.statusText ? detail : "";
    // With sign-in on, a 401 means the session ended: back to the sign-in
    // screen, keeping the hash so the reader returns to the same page. A 403
    // naming a pending password change sends them to choose one.
    if (response.status === 401 && state.auth.login_enabled && !AUTH_PATHS.test(path)) {
      sessionExpired();
    } else if (response.status === 403 && detail === PASSWORD_CHANGE_REQUIRED) {
      showPasswordScreen({forced: true});
    }
    throw err;
  }
  const type = response.headers.get("content-type") || "";
  return type.includes("application/json") ? response.json() : response.text();
}

function number(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

// "1 store", "3 stores": a count and its noun, never "store(s)".
function plural(count, singular, pluralForm = `${singular}s`) {
  const n = Number(count || 0);
  return `${number(n)} ${n === 1 ? singular : pluralForm}`;
}

function observedNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? number(value) : "Unknown";
}

// A validation failure arrives as a list of objects, one per field. Passing
// that straight to Error() produced "[object Object]" — which is what every
// form in the console showed when a required field was missing.
function describeDetail(detail) {
  if (!detail) return "";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const lines = detail.map(item => {
      if (typeof item === "string") return item;
      // `loc` is ["body", "field"] or ["query", "param"]; the field is what the
      // reader needs, not the part of the request it arrived in.
      const where = Array.isArray(item?.loc)
        ? item.loc.filter(part => !["body", "query", "path"].includes(part)).join(".")
        : "";
      const message = item?.msg || item?.message || JSON.stringify(item);
      return where ? `${where}: ${message}` : message;
    }).filter(Boolean);
    return [...new Set(lines)].join("; ");
  }
  if (typeof detail === "object") return detail.msg || detail.message || JSON.stringify(detail);
  return String(detail);
}

function unavailableReason(error) {
  // A 403 that names its reason (a role, a second person) says it; a bare one
  // cannot say more than that access was refused.
  if (error.status === 403 && error.detail && !/^forbidden\.?$/i.test(error.detail)) {
    return `Access restricted. ${refusalText(error)}`;
  }
  if (error.status === 401 || error.status === 403) return "Access restricted. Check your credentials and permissions.";
  return error.message || "Data is unavailable.";
}

function requireHistory(data) {
  if (data.available === false) throw new Error(data.message || "History is disabled or unavailable.");
  if (data.message) throw new Error(data.message);
  return data;
}

function setHealth(kind, text) {
  const node = document.querySelector(".health");
  if (node) {
    node.className = `health ${kind}`;
    node.textContent = text;
  }
}

function toast(message, type = "ok") {
  const node = h("div", {class: `toast ${type}`, role: type === "err" ? "alert" : "status"}, message);
  document.body.append(node);
  setTimeout(() => node.remove(), 4200);
}

// A panel's title is a heading (h2, under the page's h1), so the page can be
// navigated by headings and the sections inside a panel can be h3.
//
// Options, all optional: `className` is added after "panel"; `id`, `label`
// (aria-label) and `dataset` go on the section; `headingId` names the h2 and,
// unless `labelledBy` says otherwise, labels the section by it. A panel with
// no title is a plain surface: just the body.
function panel(title, body, actions, {id, className, label, labelledBy, headingId, dataset} = {}) {
  return h("section", {class: className ? `panel ${className}` : "panel", id, "aria-label": label,
                       "aria-labelledby": labelledBy || headingId, dataset},
    title ? h("div", {class: "panel-title"}, h("h2", {class: "panel-heading", id: headingId}, title), actions || "") : "",
    h("div", {class: "panel-body"}, body));
}

// The row a table shows when it has none. A string becomes the console's
// "empty" line; a node (an empty state with an action) is used as it is.
function emptyRow(columns, empty = "No records.") {
  return h("tr", {}, h("td", {colspan: columns},
    typeof empty === "string" ? h("div", {class: "empty"}, empty) : empty));
}

// The frame every table in the console shares: a scrolling wrap, the header
// row and a body. `opts.wrapClass` replaces "table-wrap"; `opts.tableClass`
// and `opts.id` go on the <table>. Header entries are strings, {sr: "Name"}
// for a column with no visible heading, or {label, sortKey, srLabel,
// className, title, defaultDir}; one with a sortKey and an `opts.sort`
// ({key, dir, onSort}) renders as a sort button with aria-sort.
//
// `opts.wrapAttrs` adds attributes to the wrap, such as a scroll region's
// role, name and tabindex.
function tableFrame(headers, tbody, {wrapClass = "table-wrap", wrapAttrs = {}, tableClass, id, sort} = {}) {
  const head = h("tr", {});
  const drawHead = current => head.replaceChildren(...headers.map(x => headerCell(x, current)));
  drawHead(sort);
  const node = h("div", {...wrapAttrs, class: wrapClass},
    h("table", {class: tableClass, id}, h("thead", {}, head), tbody));
  return {node, drawHead};
}

function table(headers, rows, opts = {}) {
  labelCells(headers, rows);
  const tbody = h("tbody", {}, rows.length ? rows : emptyRow(headers.length, opts.empty));
  return tableFrame(headers, tbody, opts).node;
}

// A table whose body is redrawn: filters, paging, "load more". setRows()
// stamps each cell's column name for the narrow layout and shows the empty
// row when there is nothing (`empty` overrides opts.empty for that draw).
// The body starts empty unless opts.rows is given. A sortable table keeps its
// own sort state: a header click flips the direction (a new column starts at
// its defaultDir, else ascending), redraws aria-sort, then calls
// opts.sort.onSort(key, dir) for the caller to reorder and setRows again.
function dataTable(headers, opts = {}) {
  const tbody = h("tbody", {});
  let sort = opts.sort ? {key: opts.sort.key, dir: opts.sort.dir} : null;
  const pickSort = (key, dir) => {
    sort = {key, dir};
    frame.drawHead({...sort, onSort: pickSort});
    opts.sort.onSort?.(key, dir);
  };
  const frame = tableFrame(headers, tbody, {...opts, sort: sort && {...sort, onSort: pickSort}});
  function setRows(rows, {empty = opts.empty} = {}) {
    labelCells(headers, rows);
    tbody.replaceChildren(...(rows.length ? rows : [emptyRow(headers.length, empty)]));
  }
  if (opts.rows) setRows(opts.rows);
  return {node: frame.node, tbody, setRows, sortState: () => sort && {key: sort.key, dir: sort.dir}};
}

// One header cell. A sortable column is a button inside the th, and the th
// carries aria-sort: "none" until it is the sorted column. A click asks for
// the other direction on the sorted column, or the column's defaultDir
// (ascending unless it says) on any other: onSort(key, dir).
function headerCell(header, sort) {
  const sortable = header && typeof header === "object" && header.sortKey && sort && sort.onSort;
  if (!sortable) return tableHeader(header);
  const key = header.sortKey;
  const name = header.label;
  const active = sort.key === key;
  const dir = sort.dir;
  const next = active ? (dir === "asc" ? "desc" : "asc") : (header.defaultDir || "asc");
  return h("th", {scope: "col", class: header.className,
                  "aria-sort": active ? (dir === "asc" ? "ascending" : "descending") : "none"},
    h("button", {class: "th-sort", type: "button", onclick: () => sort.onSort(key, next),
                 title: header.title || `Sort by ${String(name).toLowerCase()}`},
      name, h("span", {class: `th-sort-dir${active ? " is-on" : ""}`, "aria-hidden": "true"},
        active ? (dir === "asc" ? "↑" : "↓") : "↕")));
}

// Below 900px each row becomes a card and the header row is hidden, so every
// cell has to carry its own column name. Stamping it here means every table in
// the console gets it, including ones written before this existed. A cell
// that spans columns (a form opened under its row) belongs to none of them,
// so it takes no name and spans the card.
function labelCells(headers, rows) {
  const names = headers.map(header =>
    header && typeof header === "object"
      ? (typeof header.label === "string" && header.label ? header.label : header.srLabel || header.sr || "")
      : String(header || ""));
  for (const row of rows || []) {
    // `children` is an HTMLCollection in a browser, not an array.
    Array.from(row.children || []).forEach((cell, index) => {
      if (Number(cell.getAttribute?.("colspan")) > 1) return;
      if (cell.setAttribute && names[index]) cell.setAttribute("data-label", names[index]);
    });
  }
  return rows;
}

// A column with no visible heading still needs one for anyone who cannot see
// the layout. Pass {sr: "Select"} to name it without showing it. An object
// header ({label, srLabel, className}) shows its label, which may be a node
// such as a select-all box, or else names the column for screen readers only.
function tableHeader(header) {
  if (header && typeof header === "object" && header.sr) {
    return h("th", {scope: "col"}, h("span", {class: "sr-only"}, header.sr));
  }
  if (header && typeof header === "object" && !(header instanceof Node)) {
    return h("th", {scope: "col", class: header.className},
      header.label != null && header.label !== ""
        ? header.label
        : h("span", {class: "sr-only"}, header.srLabel || "Actions"));
  }
  if (!header) return h("th", {scope: "col"}, h("span", {class: "sr-only"}, "Actions"));
  return h("th", {scope: "col"}, header);
}

// Label and value pairs as a <dl>. Items are [label, value, note] or
// {label, value, note}; a falsy item is dropped. `itemClass` wraps each pair
// in a div of that class (the page-fact shape); without it the dt and dd sit
// directly in the list (the kv shape). `valueClass` wraps the value in a span,
// `noteClass` adds the note as a span after it, `ddClass` goes on every dd,
// and `skipEmpty` leaves out a pair whose value is empty.
function factList(items, {className, itemClass, valueClass, noteClass, ddClass, skipEmpty = false} = {}) {
  const fact = item => {
    const [label, value, note] = Array.isArray(item) ? item : [item.label, item.value, item.note];
    if (skipEmpty && !value) return "";
    const dt = h("dt", {}, label);
    const dd = h("dd", {class: ddClass},
      valueClass ? h("span", {class: valueClass}, value) : value,
      noteClass ? (note ? h("span", {class: noteClass}, note) : "") : null);
    return itemClass ? h("div", {class: itemClass}, dt, dd) : [dt, dd];
  };
  return h("dl", {class: className}, items.filter(Boolean).flatMap(fact));
}

// A list's filter bar: its search, filters and result count in one row,
// named for a screen reader as a search landmark. `className` is added after
// "toolbar".
function toolbar(label, children, {className} = {}) {
  return h("div", {class: className ? `toolbar ${className}` : "toolbar", role: "search", "aria-label": label},
    children);
}

// The head of a saved record's page (an audit, a scan, a privacy request):
// one surface with the record's facts in a row and its one action beside
// them, then the notes that qualify it (coverage, provenance) and where to go
// next. `meta` is a list of nodes; `action` a button or a small fact list;
// `notes` statusLines, or "" for one that does not apply.
function recordHead({meta = [], action = "", notes = [], nextSteps = ""} = {}) {
  return panel(null, [
    h("div", {class: "archive-head-row"},
      h("div", {class: "archive-head-text"}, h("div", {class: "archive-head-meta"}, ...meta)),
      action || ""),
    ...notes,
    nextSteps || ""], null, {className: "archive-head"});
}

// A tab list with the ARIA pattern: role tablist/tab/tabpanel, aria-selected,
// aria-controls, the panel labelled by its tab, and Left/Right/Home/End moving
// the selection and focus. Tabs are [key, label, count?]; a count shows as
// "Label (n)". Tab ids are `${id}-tab-${key}`; the panel id is `panelId`
// (default `${id}-tabpanel`). Pass `panel` to make an existing element the
// tab panel, or `panelClass` for the one created here.
//
// On a page every tab stays in the Tab order (the keyboard gate forbids
// tabindex=-1 on page controls). `roving: true` keeps only the selected tab
// tabbable and makes the panel focusable, which is the dialog pattern.
//
// onSelect(key, {focus}) runs when the reader picks a tab; select(key) only
// redraws the selection, so a caller can call it from its own onSelect.
function tabList({id, label, tabs, current, onSelect, roving = false, className = "tabs",
                  panel: panelNode = null, panelId = `${id}-tabpanel`, panelClass, dataKey} = {}) {
  let selected = current;
  const tabId = key => `${id}-tab-${key}`;
  const bar = h("div", {class: className, role: "tablist", "aria-label": label});
  const keys = tabs.map(([key]) => key);
  const buttons = tabs.map(([key, text, count]) => h("button", {
    class: `tab${key === selected ? " tab-active" : ""}`, type: "button", role: "tab",
    id: tabId(key), "aria-controls": panelId, dataset: dataKey ? {[dataKey]: key} : null,
    "aria-selected": keys.includes(selected) ? String(key === selected) : null,
    tabindex: roving ? (key === selected ? "0" : "-1") : null,
    onclick: () => activate(key, false),
  }, count == null ? text : `${text} (${count})`));
  bar.append(...buttons);
  const panel = panelNode || h("div", {role: "tabpanel", id: panelId, class: panelClass});
  if (panelNode) {
    panel.setAttribute("role", "tabpanel");
    panel.setAttribute("id", panelId);
  }
  if (roving) panel.setAttribute("tabindex", "0");
  if (keys.includes(selected)) panel.setAttribute("aria-labelledby", tabId(selected));

  function select(key, {focus = false} = {}) {
    if (!keys.includes(key)) return;
    selected = key;
    buttons.forEach((button, index) => {
      const on = keys[index] === key;
      button.className = on ? "tab tab-active" : "tab";
      button.setAttribute("aria-selected", String(on));
      if (roving) button.setAttribute("tabindex", on ? "0" : "-1");
    });
    panel.setAttribute("aria-labelledby", tabId(key));
    if (focus) buttons[keys.indexOf(key)]?.focus?.();
  }
  function activate(key, focus) {
    select(key, {focus});
    onSelect?.(key, {focus});
  }
  bar.addEventListener("keydown", event => {
    const at = keys.indexOf(selected);
    const to = {ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: keys.length - 1}[event?.key];
    if (to === undefined) return;
    event.preventDefault?.();
    activate(keys[(to + keys.length) % keys.length], true);
  });
  return {bar, panel, buttons, select, current: () => selected};
}

// A toggle group: one button per option, the chosen one pressed. It is a set
// of toggles, not tabs, so it is a role=group with aria-pressed. A pick marks
// the button and then calls onPick(value); with `navigates: true` it only
// calls onPick, because the route it goes to redraws the group. `className`
// is added after "segmented"; `dataKey` stamps each button with
// data-<key>=value and `controls(value)` names the element a button shows.
function segmented({label, className, options, value, onPick, dataKey, controls, navigates = false} = {}) {
  const group = h("div", {class: className ? `segmented ${className}` : "segmented", role: "group",
                          "aria-label": label});
  const buttons = options.map(([key, text]) => h("button", {
    class: `seg${key === value ? " seg-on" : ""}`, type: "button", "aria-pressed": String(key === value),
    "aria-controls": controls ? controls(key) : null, dataset: dataKey ? {[dataKey]: key} : null,
    onclick: () => {
      if (!navigates) {
        buttons.forEach((button, index) => {
          const on = options[index][0] === key;
          button.className = on ? "seg seg-on" : "seg";
          button.setAttribute("aria-pressed", String(on));
        });
      }
      onPick?.(key);
    },
  }, text));
  group.append(...buttons);
  return group;
}

// A path of steps as an ordered list: every step before `at` is done, `at` is
// current (or failed, with `failed`), the rest are to do. The current step
// carries aria-current="step" unless `ariaCurrent` is false. `itemClass(state)`
// picks each item's class (default is-done / is-current / is-failed / none);
// `srPrefix` reads the state before each step to a screen reader; `render`
// draws a step's contents (default: its label). `wrap` ({tag, className,
// label, after}) puts the list inside a labelled container, with `after`
// following it.
const STEP_CLASS = {done: "is-done", current: "is-current", failed: "is-failed"};
const STEP_SR = {done: "done: ", current: "current: ", failed: "failed: ", todo: "to do: "};

function stepList(steps, at, {label, className, failed = false, srPrefix = false, itemClass = null,
                              render = null, ariaCurrent = true, wrap = null} = {}) {
  const list = h("ol", {class: className, "aria-label": wrap ? null : label},
    steps.map((step, i) => {
      const state = i < at ? "done" : i === at ? (failed ? "failed" : "current") : "todo";
      const here = i === at;
      return h("li", {
        class: itemClass ? itemClass(state) : STEP_CLASS[state] || "",
        "aria-current": ariaCurrent && here ? "step" : null,
      },
        srPrefix ? h("span", {class: "sr-only"}, STEP_SR[state]) : null,
        render ? render(step, state, i) : step);
    }));
  if (!wrap) return list;
  return h(wrap.tag || "div", {class: wrap.className, "aria-label": label}, list, wrap.after ?? "");
}

// A row of KPI tiles. The column count follows the number of tiles, so six
// tiles make one row of six (or two of three) rather than five and an orphan;
// below 900px an odd last tile spans the row.
function kpiGrid(extraClass, ...tiles) {
  const list = tiles.flat().filter(Boolean);
  return h("div", {class: `grid kpi kpi-${Math.min(list.length, 7)}${extraClass ? ` ${extraClass}` : ""}`}, list);
}

function metric(label, value, sub) {
  return h("div", {class: "card"},
    h("div", {class: "metric-k"}, label),
    h("div", {class: "metric-v"}, value),
    h("div", {class: "metric-s"}, sub || ""));
}

// Severity carries an icon and a label as well as a colour: a red badge and an
// orange one are indistinguishable to a reader with deuteranopia, and severity
// is the field this console exists to communicate.
const SEVERITY_GLYPH = {
  critical: "sev-critical", high: "sev-high", medium: "sev-medium",
  low: "sev-low", info: "sev-info", ok: "sev-ok", unknown: "sev-unknown",
};

function badge(value) {
  const sev = String(value || "info").toLowerCase();
  return h("span", {class: `badge sev-${sev}`},
    icon(SEVERITY_GLYPH[sev] || "sev-info"), sev.toUpperCase());
}

// A state that is not a severity: it borrows the palette for its tone but shows
// its own name. Passing a tone to badge() printed the tone as the label, which
// is how "new" came to render as "UNKNOWN".
//
// This is the console's one status chip: an icon and a label on the tone's
// soft background. Every status (coverage, case, crypto, evidence, exception,
// run, privacy request, reachability) goes through it or through badge(),
// which is the same chip for a severity. `.tag` is only for neutral metadata.
function stateChip(tone, label, {glyph = "", title = ""} = {}) {
  const key = String(tone || "info").toLowerCase();
  return h("span", {class: `badge sev-${key}`, title: title || null},
    icon(glyph || SEVERITY_GLYPH[key] || "sev-info"),
    String(label || "").replace(/_/g, " "));
}

// Coverage of a run. Complete, partial, or not known: partial is never a
// pass, and unknown is dashed so it never reads as a result.
function coverageChip(status) {
  const value = String(status || "unknown");
  const tone = value === "complete" ? "ok" : value === "partial" ? "medium" : "unknown";
  return stateChip(tone, value);
}

// How a run or saved audit ended, as far as execution goes. Coverage is a
// separate chip: a run can complete and still cover only part of its scope.
// A check's outcome. Skipped and unsupported are limits, not failures, and
// inconclusive is not a pass.
// A state looked up in a table of tones. An entry is a tone (the value is its
// own label) or {tone, text}; a value the table does not know is "unknown",
// labelled as it came, never borrowed from a neighbouring state.
function toneChip(tones, value) {
  const meta = tones[value];
  if (!meta) return stateChip("unknown", String(value || "unknown"));
  return typeof meta === "string" ? stateChip(meta, value) : stateChip(meta.tone, meta.text);
}

const OUTCOME_TONE = {passed: "ok", failed: "critical", inconclusive: "medium"};
const EXECUTION_STATE = {
  complete: {tone: "ok", text: "complete"}, completed: {tone: "ok", text: "completed"},
  partial: {tone: "medium", text: "partial"}, error: {tone: "critical", text: "error"},
};

function outcomeChip(outcome) {
  return toneChip(OUTCOME_TONE, String(outcome || "unknown"));
}

function executionChip(status) {
  const value = String(status || "unknown");
  return toneChip(RUN_STATE[value] ? RUN_STATE : EXECUTION_STATE, value);
}

// A severity's count as a number, or null when it was not reported. Null is
// shown as "Unknown": a count nobody sent is not a count of zero.
function severityCount(counts, sev) {
  const value = counts && typeof counts === "object" ? counts[sev] : undefined;
  if (value == null || value === "") return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

// Counts by severity, in one shape wherever the console shows them: always in
// severityOrder, each severity with its glyph and its name, so colour is
// never the only cue, and a count that was not reported reads "Unknown",
// never 0.
//
// - "list": a row per severity, glyph and label on the left, the count on the
//   right. `link(sev)` gives [view, params], or `onPick(sev)` runs, to make each
//   row a button; `active(sev)` marks a pressed row. `empty` (nothing measured
//   yet) and `unavailable` (the counts could not be read) blank every count,
//   say why, and link nowhere. `sub` is a caption under the rows; `total`
//   (when given, even as undefined) adds a Total row above them. `columns`
//   lays the rows side by side, a figure under each label, for a page wide
//   enough to read them in one line.
// - "strip": the Findings filter chips (.fsum-chip, .fsum-n, .fsum-k,
//   aria-pressed; a zero chip that is not on is disabled). `heading` is the
//   group's visible label, `groupLabel` its accessible name and `title(sev,
//   on)` each chip's title; no counts at all reads `unavailable`.
// - "inline": the severities with findings as compact glyph + count pairs.
//   None reads "none observed", inconclusive unless `complete` says coverage
//   was complete for the declared scope.
// `label(sev)` names a severity: capitalised in a list, lower case elsewhere;
// `className` is added to the list's own.
function severitySummary(counts, opts = {}) {
  const {variant = "list", label, sub = "", link, onPick, active, empty = "", unavailable = "",
         complete = false, heading = "Severity", groupLabel = "Filter by severity", title,
         columns = false, className = ""} = opts;
  const name = sev => (label ? label(sev) : variant === "list" ? severityName(sev) : sev);
  const isOn = sev => Boolean(typeof active === "function" ? active(sev) : active && active === sev);
  const glyph = sev => icon(SEVERITY_GLYPH[sev] || "sev-info");

  if (variant === "inline") {
    if (!counts || typeof counts !== "object") {
      return h("span", {class: "sev-counts sub", title: "No severity counts were recorded for this result."},
        "Unknown");
    }
    const present = severityOrder.filter(s => (severityCount(counts, s) || 0) > 0);
    if (!present.length) {
      return h("span", {class: "sev-counts sub", title: complete ? "" :
        "Zero observed findings under partial or unknown coverage is inconclusive, not clean."},
        complete ? "none observed" : "none observed · inconclusive");
    }
    return h("span", {class: "sev-counts"}, present.map(s =>
      h("span", {class: `sev-count sev-${s}`, title: `${number(counts[s])} ${s}`},
        glyph(s),
        h("span", {class: "sev-count-n"}, number(counts[s])),
        h("span", {class: "sr-only"}, ` ${s}`))));
  }

  if (variant === "strip") {
    const group = h("div", {class: "fsum-group", role: "group", "aria-label": groupLabel},
      h("span", {class: "fsum-label"}, heading));
    if (!counts) {
      group.append(h("span", {class: "sub"}, unavailable || "Counts unavailable"));
      return group;
    }
    for (const sev of severityOrder) {
      const n = severityCount(counts, sev);
      const on = isOn(sev);
      group.append(h("button", {
        class: `fsum-chip sev-${sev}${on ? " is-on" : ""}`, type: "button",
        "aria-pressed": String(on), disabled: n === 0 && !on,
        title: title ? title(sev, on) : `Show only ${sev}`,
        onclick: () => onPick?.(sev),
      }, glyph(sev), h("span", {class: "fsum-n"}, observedNumber(n)),
         h("span", {class: "fsum-k"}, name(sev))));
    }
    return group;
  }

  // The list. A blank is either "nothing to count yet" or "could not be
  // read"; each row says which to a screen reader, and the reason shows once.
  const blank = unavailable || empty;
  const linked = Boolean(!blank && (link || onPick));
  // The spaces between the parts keep a row's accessible name "Critical 1"
  // rather than "Critical1"; a grid does not render them.
  const cell = (key, glyphNode, text, n) => [
    h("span", {class: glyphNode ? `sev-summary-icon sev-${key}` : "sev-summary-icon"}, glyphNode || ""),
    h("span", {class: "sev-summary-k"}, text), " ",
    h("span", {class: !blank && n != null ? "sev-summary-n" : "sev-summary-n is-unknown"},
      unavailable ? "Unavailable" : empty ? "—" : observedNumber(n)),
    blank ? h("span", {class: "sr-only"}, ` ${blank}`) : null,
  ];
  const rows = severityOrder.map(sev => {
    const parts = cell(sev, glyph(sev), name(sev), severityCount(counts, sev));
    if (!linked) return h("li", {class: "sev-summary-row"}, ...parts);
    const on = isOn(sev);
    return h("li", {},
      h("button", {class: `sev-summary-row${on ? " is-on" : ""}`, type: "button",
                   "aria-pressed": active ? String(on) : null,
                   onclick: () => {
                     if (onPick) return onPick(sev);
                     const [view, params] = link(sev);
                     goTo(view, params || {});
                   }}, ...parts, h("span", {class: "sev-summary-go"}, icon("chevron-right"))));
  });
  // A total, when the caller has one, leads; it is not a severity, so it has
  // no glyph and no link.
  if (Object.prototype.hasOwnProperty.call(opts, "total")) {
    rows.unshift(h("li", {class: "sev-summary-row is-total"},
      ...cell("total", null, "Total", severityCount({total: opts.total}, "total"))));
  }
  return h("div", {class: ["sev-summary", columns ? "is-columns" : "", linked ? "is-linked" : "", className]
                     .filter(Boolean).join(" ")},
    blank ? h("p", {class: "sev-summary-note", "aria-hidden": "true"}, blank) : "",
    h("ul", {class: "sev-summary-list"}, rows),
    sub ? h("p", {class: "sev-summary-sub"}, sub) : "");
}

// Timestamps are for reading, not parsing. Show a short absolute date with the
// relative age beside it, and never print a raw ISO string in a table.
// One parser for both shapes the backend emits: ISO strings everywhere, and
// epoch seconds in the audit log. Every time display goes through this, so a
// raw float can never reach a table again.
function toMillis(value) {
  if (value == null || value === "") return NaN;
  const numeric = typeof value === "number" ? value : Number(value);
  if (Number.isFinite(numeric)) return numeric > 1e11 ? numeric : numeric * 1000;
  return Date.parse(value);
}

//
// Relative age first ("3 h ago"), then the reader's local date and time. The
// exact ISO instant is in the title (hover) and the datetime attribute, for
// anyone who needs to compare it with a log line. A reader who lines times up
// with UTC logs can choose UTC in Settings; the choice is kept in this browser
// and changes only what the console shows, never an export or evidence.
const TIME_KEY = "vecshield_time";

function storedTimeZone() {
  try {
    return globalThis.localStorage?.getItem?.(TIME_KEY) === "utc" ? "utc" : "local";
  } catch { return "local"; } // blocked storage or private mode
}

function timeFormatter(zone) {
  return new Intl.DateTimeFormat(undefined, {dateStyle: "medium", timeStyle: "short",
                                             ...(zone === "utc" ? {timeZone: "UTC"} : {})});
}

let timeZoneChoice = storedTimeZone();
let LOCAL_TIME = timeFormatter(timeZoneChoice);

function setTimeZone(zone) {
  timeZoneChoice = zone === "utc" ? "utc" : "local";
  try {
    if (timeZoneChoice === "utc") localStorage.setItem(TIME_KEY, "utc");
    else localStorage.removeItem(TIME_KEY);
  } catch { /* storage blocked: the choice lasts for this page only */ }
  LOCAL_TIME = timeFormatter(timeZoneChoice);
}

function localTime(value) {
  const millis = toMillis(value);
  if (!Number.isFinite(millis)) return String(value ?? "");
  const text = LOCAL_TIME.format(new Date(millis));
  return timeZoneChoice === "utc" ? `${text} UTC` : text;
}

function formatWhen(value) {
  if (value == null || value === "") return h("span", {class: "sub"}, "-");
  const millis = toMillis(value);
  if (!Number.isFinite(millis)) return h("span", {class: "mono"}, String(value));
  const iso = new Date(millis).toISOString();
  return h("time", {class: "when", datetime: iso, title: iso},
    h("span", {class: "when-rel"}, relativeTime(value)),
    h("span", {class: "sub when-abs"}, localTime(value)));
}

// Minutes and hours for the recent past, whole days after that.
function relativeTime(when) {
  const then = toMillis(when);
  if (!Number.isFinite(then)) return String(when || "unknown");
  const diff = Date.now() - then;
  const abs = Math.abs(diff);
  const ago = text => (diff >= 0 ? `${text} ago` : `in ${text}`);
  if (abs < 60000) return diff >= 0 ? "just now" : "in under a minute";
  if (abs < 3600000) return ago(`${Math.round(abs / 60000)} min`);
  if (abs < 86400000) return ago(`${Math.round(abs / 3600000)} h`);
  return relativeDay(when);
}

function field(label, input) {
  return h("label", {class: "field"}, h("span", {}, label), input);
}

// An info glyph that shows its text on hover or focus. The popup is out of
// layout until then, so the glyph carries the text itself, as a named image.
// On a touch screen a tap is the hover: it focuses the glyph, which shows the
// tip, and a tap elsewhere hides it (the document's click listener). Inside a
// label the tap must not also tick the box that label names.
function tooltip(text) {
  const tip = h("span", {class: "tip", tabindex: "0", role: "img", "aria-label": text},
    icon("info"),
    h("span", {class: "tip-pop", role: "tooltip"}, text));
  tip.addEventListener("click", event => {
    event?.preventDefault?.();
    tip.focus?.();
  });
  return tip;
}

// A box with no words of its own (a row's select box) inside a label, so that
// on a touch screen its target can be 44px without the box itself moving.
function hitBox(input) {
  return h("label", {class: "hit"}, input);
}

function fieldTip(label, input, help) {
  return h("label", {class: "field"},
    h("span", {}, label, help ? tooltip(help) : ""),
    input);
}

function textInput(value = "", attrs = {}) {
  const input = h("input", {type: attrs.type || "text", value, ...attrs});
  input.value = value || "";
  return input;
}

function selectInput(options, value = "", attrs = {}) {
  const sel = h("select", attrs, options.map(([val, label]) => h("option", {value: val, selected: val === value}, label)));
  sel.value = value || "";
  return sel;
}

// The Clipboard API is unavailable outside a secure context, so on a console
// served over plain HTTP — which a self-hosted deployment often is — the
// promise rejects and the button does nothing at all. Fall back to a selection
// the reader can copy, and say what happened when even that is not possible.
async function copyText(text, what = "Text") {
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      toast(`${what} copied.`);
      return true;
    }
  } catch { /* fall through to the manual path */ }

  try {
    const area = h("textarea", {readonly: true, "aria-label": `${what} to copy`});
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.append(area);
    area.select();
    const copied = document.execCommand?.("copy");
    area.remove();
    if (copied) {
      toast(`${what} copied.`);
      return true;
    }
  } catch { /* fall through to showing it */ }

  // Never fail silently: show the text so it can be copied by hand.
  modal(`${what}`, h("div", {},
    statusLine("This browser will not let the page write to the clipboard " +
               "(usually because the console is not served over HTTPS). " +
               "Select the text below and copy it.", "medium"),
    h("pre", {}, text)), null, "Close", {stack: true});
  return false;
}

// A record as a short key/value list rather than pretty-printed JSON: nested
// keys are flattened ("scope / store"), timestamps read as local time, and a
// long record shows its first entries with the rest one click away.
const ISO_INSTANT = /^\d{4}-\d\d-\d\dT\d\d:\d\d/;

function kvValue(value) {
  if (typeof value === "string" && ISO_INSTANT.test(value)) {
    return h("span", {title: value}, localTime(value));
  }
  if (typeof value === "boolean") return value ? "yes" : "no";
  return shortValue(value);
}

function kvList(value, {limit = 6} = {}) {
  const entries = flattenEntries(value || {}).filter(e => e.key);
  if (!entries.length) return h("span", {class: "sub"}, "-");
  const row = e => [h("dt", {}, prettyKey(e.key)), h("dd", {title: typeof e.value === "string" ? e.value : null}, kvValue(e.value))];
  const shown = entries.slice(0, limit);
  const rest = entries.slice(limit);
  return h("div", {class: "kv-compact-wrap"},
    h("dl", {class: "kv-compact"}, shown.flatMap(row)),
    rest.length
      ? h("details", {class: "evidence-data"},
          h("summary", {}, icon("list"), `${number(rest.length)} more`),
          h("dl", {class: "kv-compact"}, rest.flatMap(row)))
      : "");
}

function jsonBlock(value) {
  return h("pre", {}, JSON.stringify(value || {}, null, 2));
}

function normalizeText(value) {
  return String(value ?? "")
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[_./:()[\]{}-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// ----------------------------------------------------------------- charts ---
// Hand-rolled SVG: the console's CSP forbids external scripts, and that is the
// right constraint. Every chart here carries an accessible name, a data table
// underneath it, and a pattern rather than relying on colour, because these
// charts report coverage and severity — the two things a reader must not
// misread. Nothing interpolates across a gap: a day with no run draws no bar.

const CHART_PATTERNS = ["hatch-unknown"];

function chartDefs() {
  return h("defs", {},
    h("pattern", {id: "hatch-unknown", width: "6", height: "6",
                  patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)"},
      h("rect", {width: "6", height: "6", fill: "var(--surface-3)"}),
      h("line", {x1: "0", y1: "0", x2: "0", y2: "6",
                 stroke: "var(--unknown)", "stroke-width": "2"})));
}

function chartFrame(label, description, body, dataTable, {width = 640, height = 200, legend = null} = {}) {
  return h("figure", {class: "chart"},
    h("svg", {class: "chart-svg", viewBox: `0 0 ${width} ${height}`, role: "img",
              "aria-label": label, preserveAspectRatio: "xMidYMid meet"},
      h("title", {}, label), chartDefs(), body),
    legend || "",
    h("figcaption", {class: "sub"}, description),
    h("details", {class: "evidence-data chart-data"},
      h("summary", {}, icon("list"), "Data table"), dataTable));
}

// Findings per day. Bars, not a line: a line would draw straight through days
// when nothing ran, which is an interpolation the data does not support.
//
// Each bar is stacked from the stores that ran that day, worst first, and each
// segment takes the colour of the worst severity *that store* recorded. The
// history keeps a day's count and its worst severity per store, not a count
// per severity, so the chart says exactly that rather than painting a whole
// day's findings the colour of its single worst one.
function trendChart(trend, {days = 30} = {}) {
  // Newer servers send each row's findings split by severity; with that the
  // bars are a true per-severity stack. Older ones send only a store's worst
  // severity, and each segment is then that store, in its worst colour.
  const perSeverity = (trend || []).some(row => row && typeof row.by_severity === "object" && row.by_severity);
  const byDay = new Map();
  for (const row of trend || []) {
    const day = String(row.day || "").slice(0, 10);
    if (!day) continue;
    const prior = byDay.get(day) || {findings: 0, severity: "info", stores: new Set(), segments: [], bySev: {}};
    prior.findings += Number(row.findings || 0);
    if (severityMeets(row.max_severity, prior.severity)) prior.severity = row.max_severity;
    prior.stores.add(row.store);
    if (perSeverity) {
      for (const sev of severityOrder) prior.bySev[sev] = (prior.bySev[sev] || 0) + Number((row.by_severity || {})[sev] || 0);
      prior.segments = severityOrder.map(sev => ({store: "all stores", findings: prior.bySev[sev], severity: sev}));
    } else {
      prior.segments.push({store: row.store, findings: Number(row.findings || 0),
                           severity: severityOrder.includes(row.max_severity) ? row.max_severity : "info"});
    }
    byDay.set(day, prior);
  }

  const today = new Date();
  const slots = [];
  for (let i = days - 1; i >= 0; i -= 1) {
    const date = new Date(today.getTime() - i * 86400000);
    const key = date.toISOString().slice(0, 10);
    slots.push({day: key, data: byDay.get(key) || null});
  }

  const peak = Math.max(1, ...slots.map(s => (s.data ? s.data.findings : 0)));
  // Wide and short: at console widths the chart is drawn near 1:1, so it
  // takes about 160px rather than a third of the screen. On a phone it is
  // drawn for a phone, read once when it is drawn: the wide view, shrunk to
  // a phone's width, set its 11px labels at about 4px.
  const narrow = Boolean(globalThis.matchMedia?.("(max-width: 640px)")?.matches);
  const width = narrow ? 340 : 1000, height = narrow ? 180 : 160;
  const pad = {top: 14, right: 10, bottom: 26, left: 34};
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const slotW = plotW / slots.length;
  const shortDay = day => {
    const date = new Date(`${day}T12:00:00Z`);
    return Number.isFinite(date.getTime())
      ? date.toLocaleDateString(undefined, {month: "short", day: "numeric"}) : day;
  };

  const bars = slots.map((slot, index) => {
    const x = pad.left + index * slotW;
    if (!slot.data) {
      // No run that day: a hatched floor tile, never a zero bar.
      return h("rect", {x: String(x + slotW * 0.15), y: String(pad.top + plotH - 3),
                        width: String(Math.max(1, slotW * 0.7)), height: "3",
                        fill: "url(#hatch-unknown)"});
    }
    if (!slot.data.findings) {
      // A run that recorded nothing still draws a sliver, so the day reads as
      // measured, not as missing.
      return h("rect", {x: String(x + slotW * 0.15), y: String(pad.top + plotH - 2),
                        width: String(Math.max(1, slotW * 0.7)), height: "2",
                        class: "bar sev-fill-ok"});
    }
    let y = pad.top + plotH;
    const ordered = [...slot.data.segments].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    return h("g", {}, ordered.filter(seg => seg.findings > 0).map(seg => {
      const segH = Math.max(1.5, (seg.findings / peak) * plotH);
      y -= segH;
      return h("rect", {x: String(x + slotW * 0.15), y: String(y),
                        width: String(Math.max(1, slotW * 0.7)), height: String(segH),
                        class: `bar sev-fill-${seg.severity}`},
        h("title", {}, perSeverity
          ? `${shortDay(slot.day)}: ${plural(seg.findings, `${seg.severity} finding`)}`
          : `${shortDay(slot.day)} · ${seg.store}: ${plural(seg.findings, "finding")}, worst ${seg.severity}`));
    }));
  });

  const axis = [
    h("line", {x1: String(pad.left), y1: String(pad.top + plotH),
               x2: String(width - pad.right), y2: String(pad.top + plotH),
               stroke: "var(--border-strong)"}),
    h("text", {x: "4", y: String(pad.top + 10), class: "chart-tick"}, String(peak)),
    h("text", {x: "4", y: String(pad.top + plotH), class: "chart-tick"}, "0"),
    h("text", {x: String(pad.left), y: String(height - 8), class: "chart-tick"}, shortDay(slots[0].day)),
    h("text", {x: String(width - pad.right), y: String(height - 8),
               class: "chart-tick", "text-anchor": "end"}, shortDay(slots[slots.length - 1].day)),
  ];

  const recorded = slots.filter(s => s.data);
  const present = severityOrder.filter(sev => recorded.some(s => s.data.segments.some(seg => seg.severity === sev && seg.findings)));
  const dataTable = table(["Day", "Findings recorded", "Highest severity"],
    slots.map(slot => h("tr", {},
      h("td", {}, slot.day),
      h("td", {}, slot.data ? number(slot.data.findings) : "no run"),
      h("td", {}, slot.data ? badge(slot.data.severity) : h("span", {class: "sub"}, "not measured")))));

  const legend = present.length
    ? h("div", {class: "chart-legend", "aria-hidden": "true"},
        present.map(sev => h("span", {class: "chart-key"},
          h("span", {class: `chart-swatch sev-bg-${sev}`}), sev)))
    : null;
  return chartFrame(
    `Findings recorded per day over the last ${days} days`,
    `${number(recorded.length)} of ${days} days recorded a run. Days with no run are ` +
    "hatched, not zero: nothing was measured then. " +
    (perSeverity
      ? "Each bar is split by severity."
      : "Each segment is one store's findings that day, coloured by the worst severity that store recorded."),
    h("g", {}, axis, bars), dataTable, {width, height, legend});
}

// What a run actually inspected. The unmeasured segment is always drawn, even
// when it is the whole bar.
function coverageChart(coverage, {label = "Assessment coverage"} = {}) {
  const outcomes = (coverage || {}).outcomes || {};
  const expected = Math.max(1, Number(coverage?.checks_expected || 0) || 1);
  const complete = Number(coverage?.checks_complete || 0);
  const ran = (Number(outcomes.passed || 0) + Number(outcomes.failed || 0) +
               Number(outcomes.inconclusive || 0));
  const partial = Math.max(0, ran - complete);
  const unmeasured = Math.max(0, expected - complete - partial);

  const width = 640, height = 64, barY = 12, barH = 26;
  const segments = [
    ["complete", complete, "var(--ok)"],
    ["partial", partial, "var(--medium)"],
    ["unmeasured", unmeasured, "url(#hatch-unknown)"],
  ];
  let cursor = 0;
  const drawn = segments.filter(([, value]) => value > 0).map(([name, value, fill]) => {
    const segW = (value / expected) * width;
    const rect = h("rect", {x: String(cursor), y: String(barY), width: String(Math.max(2, segW)),
                            height: String(barH), fill, class: `coverage-seg coverage-${name}`});
    cursor += segW;
    return rect;
  });

  const dataTable = table(["Segment", "Checks", "Meaning"], [
    h("tr", {}, h("td", {}, "Complete"), h("td", {}, number(complete)),
      h("td", {}, "Inspected in full")),
    h("tr", {}, h("td", {}, "Partial"), h("td", {}, number(partial)),
      h("td", {}, "Ran over part of the scope; absence of a finding proves nothing")),
    h("tr", {}, h("td", {}, "Unmeasured"), h("td", {}, number(unmeasured)),
      h("td", {}, "Skipped, unsupported, or failed — never measured")),
  ]);

  const status = coverage?.status || "unknown";
  return h("figure", {class: "chart chart-coverage"},
    h("svg", {class: "chart-svg", viewBox: `0 0 ${width} ${height}`, role: "img",
              "aria-label": `${label}: ${complete} complete, ${partial} partial, ${unmeasured} unmeasured of ${expected} checks`},
      h("title", {}, label), chartDefs(), h("g", {}, drawn)),
    h("figcaption", {class: "sub"},
      `${number(complete)} complete · ${number(partial)} partial · ` +
      `${number(unmeasured)} unmeasured of ${number(expected)} checks (status: ${status})`),
    h("details", {class: "evidence-data chart-data"},
      h("summary", {}, icon("list"), "Data table"), dataTable));
}

// Collection x severity. A collection nothing inspected is hatched, so an empty
// row never reads as a clean one.
function heatmapChart(findings, {inspected = null, scope = null,
                                 label = "Findings by collection and severity"} = {}) {
  const rows = new Map();
  for (const finding of findings || []) {
    const key = finding.collection || "(store)";
    const row = rows.get(key) || {};
    row[finding.severity] = (row[finding.severity] || 0) + 1;
    rows.set(key, row);
  }
  // Every collection in the declared scope gets a row, whether or not anything
  // was found there — and whether or not it was ever reached.
  for (const name of [...(scope || []), ...(inspected || [])]) {
    if (!rows.has(name)) rows.set(name, {});
  }

  const collections = [...rows.keys()].sort();
  if (!collections.length) return emptyState("No collections were inspected.");

  const cell = 34, labelW = 150, headH = 22;
  const width = labelW + severityOrder.length * cell;
  const height = headH + collections.length * cell;
  const known = inspected ? new Set(inspected) : null;
  // `inspected` lists collections, so the store-scope row (findings with no
  // collection) is never in it. A row that holds findings was observed by
  // something; hatching it would hide what was found there.
  const measuredRow = name => !known || known.has(name) || Object.keys(rows.get(name) || {}).length > 0;
  const short = {critical: "crit", medium: "med"};

  const head = severityOrder.map((sev, index) =>
    h("text", {x: String(labelW + index * cell + cell / 2), y: "14",
               class: "chart-tick", "text-anchor": "middle"}, short[sev] || sev));

  const cells = collections.flatMap((name, rowIndex) => {
    const y = headH + rowIndex * cell;
    const measured = measuredRow(name);
    return [
      h("text", {x: "0", y: String(y + cell / 2 + 4), class: "chart-tick"}, name.slice(0, 22)),
      ...severityOrder.map((sev, colIndex) => {
        const count = (rows.get(name) || {})[sev] || 0;
        const x = labelW + colIndex * cell;
        return h("g", {},
          h("rect", {x: String(x + 1), y: String(y + 1), width: String(cell - 2),
                     height: String(cell - 2), rx: "4",
                     fill: measured ? (count ? `var(--${sev})` : "var(--surface-3)") : "url(#hatch-unknown)",
                     "fill-opacity": measured && count ? "0.85" : "1"}),
          measured
            ? h("text", {x: String(x + cell / 2), y: String(y + cell / 2 + 4),
                         class: `chart-cell ${count ? "chart-cell-on" : ""}`,
                         "text-anchor": "middle"}, String(count))
            : "");
      }),
    ];
  });

  const dataTable = table(["Collection", ...severityOrder, "Inspected"],
    collections.map(name => h("tr", {},
      h("td", {}, name),
      ...severityOrder.map(sev => h("td", {}, number((rows.get(name) || {})[sev] || 0))),
      h("td", {}, measuredRow(name) ? "yes" : "not inspected"))));

  return chartFrame(label,
    known
      ? "Hatched rows were never inspected: an empty row there is not a clean one."
      : "Counts are for findings recorded in this result.",
    h("g", {}, head, cells), dataTable, {width, height});
}

function fuzzyMatch(haystack, query) {
  const hay = normalizeText(haystack);
  const tokens = normalizeText(query).split(" ").filter(Boolean);
  if (!tokens.length) return true;
  return tokens.every(token => hay.includes(token) || isSubsequence(token, hay));
}

function isSubsequence(needle, haystack) {
  let i = 0;
  for (const ch of haystack) {
    if (ch === needle[i]) i += 1;
    if (i === needle.length) return true;
  }
  return false;
}

function flattenEntries(value, prefix = "", out = []) {
  if (value == null || typeof value !== "object") {
    if (prefix) out.push({key: prefix, value});
    return out;
  }
  if (Array.isArray(value)) {
    if (!value.length && prefix) out.push({key: prefix, value: "[]"});
    value.forEach((item, i) => {
      const key = prefix ? `${prefix}[${i}]` : `[${i}]`;
      if (item != null && typeof item === "object") flattenEntries(item, key, out);
      else out.push({key, value: item});
    });
    return out;
  }
  const entries = Object.entries(value);
  if (!entries.length && prefix) out.push({key: prefix, value: "{}"});
  for (const [key, item] of entries) {
    flattenEntries(item, prefix ? `${prefix}.${key}` : key, out);
  }
  return out;
}

function prettyKey(key) {
  return String(key || "value")
    .replace(/\[(\d+)\]/g, " $1")
    .split(".")
    .slice(-2)
    .join(" / ")
    .replaceAll("_", " ");
}

function shortValue(value) {
  if (value == null || value === "") return "-";
  const text = typeof value === "object" ? JSON.stringify(value) : String(value);
  return text.length > 72 ? `${text.slice(0, 69)}...` : text;
}

function evidenceIconName(key, value) {
  const k = String(key || "").toLowerCase();
  if (k.includes("fingerprint") || k.endsWith("id") || k.includes("hash")) return "hash";
  if (k.includes("key") || k.includes("token") || k.includes("secret")) return "key";
  if (k.includes("file") || k.includes("path") || k.includes("source") || k.includes("collection") || k.includes("store")) return "file";
  if (k.includes("severity") || k.includes("status") || k.includes("suppressed") || typeof value === "boolean") return "check";
  if (k.includes("category") || k.includes("label") || k.includes("rule")) return "tag";
  return "tag";
}

function evidenceChip(entry) {
  return h("span", {class: "evidence-chip", title: entry.title || `${entry.key}: ${shortValue(entry.value)}`},
    icon(evidenceIconName(entry.key, entry.value)),
    h("span", {class: "chip-key"}, prettyKey(entry.key)),
    h("span", {class: "chip-value"}, shortValue(entry.value)));
}

// Fields a finding row already shows in a column of its own, or that say
// nothing until they are true.
const EVIDENCE_SHOWN_ELSEWHERE = new Set(["fingerprint"]);
const EVIDENCE_CHIP_LIMIT = 8;

// One top-level evidence field as a chip, or null when it has nothing to say.
// Leaves deep inside examples and explanations are not chips: a list reads as
// its size, a count map as its largest counts, and the whole record stays one
// click away in "Evidence data".
function evidenceSummaryEntry(key, value) {
  if (EVIDENCE_SHOWN_ELSEWHERE.has(key) || value == null || value === "") return null;
  if (key === "suppressed" && value !== true) return null;
  if (Array.isArray(value)) {
    if (!value.length) return null;
    const scalars = value.every(item => item == null || typeof item !== "object");
    const text = scalars && value.length <= 3 ? value.join(", ") : `${number(value.length)} items`;
    return {key, value: text, title: `${key}: ${scalars ? value.join(", ") : `${value.length} items`}`};
  }
  if (typeof value === "object") {
    const entries = Object.entries(value).filter(([, item]) => item != null && item !== "");
    if (!entries.length) return null;
    if (entries.every(([, item]) => typeof item === "number")) {
      const ranked = entries.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([name, count]) => `${name.replaceAll("_", " ")} ${number(count)}`);
      return {key, value: ranked.join(" · "), title: `${key}: ${ranked.join(", ")}`};
    }
    return {key, value: `${number(entries.length)} fields`,
            title: `${key}: ${entries.length} fields, listed in Evidence data`};
  }
  return {key, value, title: `${key}: ${value}`};
}

function evidenceView(evidence) {
  const data = evidence || {};
  const entries = Object.entries(data)
    .map(([key, value]) => evidenceSummaryEntry(key, value))
    .filter(Boolean);
  const shown = entries.slice(0, EVIDENCE_CHIP_LIMIT);
  const hidden = entries.length - shown.length;
  return h("div", {class: "evidence-view"},
    h("div", {class: "evidence-tags"},
      shown.length ? shown.map(evidenceChip) : h("span", {class: "muted"}, "No evidence attributes"),
      hidden ? h("span", {class: "tag", title: "The remaining fields are in Evidence data."},
                 `+${number(hidden)} more ${hidden === 1 ? "field" : "fields"}`) : ""),
    h("details", {class: "evidence-data"},
      h("summary", {}, icon("code"), "Evidence data"),
      jsonBlock(data)));
}

function searchableText(value) {
  const pieces = [];
  for (const {key, value: entryValue} of flattenEntries(value || {})) {
    pieces.push(key, typeof entryValue === "object" ? JSON.stringify(entryValue) : String(entryValue ?? ""));
  }
  return pieces.join(" ");
}

function uniqueValues(items, getter) {
  return [...new Set(items.map(getter).filter(Boolean).map(String))].sort((a, b) => a.localeCompare(b));
}

function optionSet(values) {
  return [...new Set((values || []).filter(Boolean).map(String))]
    .sort((a, b) => a.localeCompare(b))
    .map(x => [x, x]);
}

function severityRank(value) {
  const idx = severityOrder.indexOf(String(value || "info").toLowerCase());
  return idx === -1 ? severityOrder.length : idx;
}

function severityMeets(value, minimum) {
  return severityRank(value) <= severityRank(minimum || "info");
}

function getPathValue(obj, path) {
  return String(path || "").split(".").reduce((cur, part) => {
    if (cur == null) return undefined;
    return cur[part];
  }, obj);
}

// Finding categories, named for a reader. An id with no entry is shown as
// itself, never dropped. The crypto categories come from the posture and
// representation checks; see CHECK_GLOSSARY for what each one observes.
const CATEGORY_LABELS = {
  any: "Any category",
  data_classification: "Data classification",
  isolation: "Tenant isolation",
  rag_integrity: "RAG integrity",
  network_exposure: "Network exposure",
  authentication: "Store authentication",
  cve: "Known CVEs",
  transport_encryption: "Transport encryption",
  transport_tls_enforcement: "TLS enforcement",
  tls_certificate_verification: "TLS certificate verification",
  at_rest_encryption: "Encryption at rest",
  field_encryption: "Field-level encryption",
  data_representation: "Sensitive data representation",
  pan_representation: "PAN representation",
  retrieval_exposure: "Retrieval exposure",
  direct_identifier_exposure: "Direct identifier exposure",
  retention_horizon: "Retention horizon",
  retention: "Retention horizon",
  embedding_consistency: "Embedding consistency",
  access_grants: "Access grants",
  server_vulnerability: "Server vulnerability",
  coverage: "Coverage",
  biometric_templates: "Biometric templates",
  nlp_classification: "NLP classification",
  retention_schedule: "Retention schedule",
  chunk_versions: "Chunk versions",
  query_result_ceiling: "Query result ceiling",
  // Pre-existing: key-audit findings carry this category and were rendering
  // as the raw key.
  access_control: "Access control",
};

function categoryLabel(category) {
  const key = String(category || "any");
  return CATEGORY_LABELS[key] || key.replace(/_/g, " ");
}

// A rule names one category or, since templates gained the crypto
// categories, several; either spelling is read.
function ruleCategories(rule = {}) {
  const raw = rule?.categories ?? rule?.category;
  if (raw == null || raw === "") return [];
  return [].concat(raw).filter(Boolean).map(String);
}

function templateCategories(t) {
  const own = t.category ? [].concat(t.category).map(String) : ruleCategories(t.when || {});
  return own.length ? own : ["any"];
}

function findingMatchesRule(finding, rule = {}) {
  if (!rule || !Object.keys(rule).length) return true;
  const categories = ruleCategories(rule);
  if (categories.length && !categories.includes(String(finding.category || ""))) return false;
  if (rule.collection && String(finding.collection || "") !== String(rule.collection)) return false;
  if (rule.min_severity && !severityMeets(finding.severity, rule.min_severity)) return false;
  if (rule.requires_label) {
    const labels = (finding.evidence || {}).label_counts || {};
    if (!Number(labels[rule.requires_label] || 0)) return false;
  }
  if (rule.evidence_gte) {
    for (const [path, threshold] of Object.entries(rule.evidence_gte)) {
      const value = Number(getPathValue(finding.evidence || {}, path));
      if (!(value >= Number(threshold))) return false;
    }
  }
  return true;
}

function ruleSummary(rule = {}) {
  const parts = [];
  const categories = ruleCategories(rule);
  if (categories.length) parts.push(`category ${categories.map(categoryLabel).join(" or ")}`);
  if (rule.requires_label) parts.push(`label ${rule.requires_label}`);
  if (rule.min_severity) parts.push(`severity >= ${String(rule.min_severity).toUpperCase()}`);
  if (rule.collection) parts.push(`collection = ${rule.collection}`);
  if (rule.evidence_gte) {
    for (const [path, value] of Object.entries(rule.evidence_gte)) parts.push(`${path} >= ${value}`);
  }
  return parts.length ? parts.join(" · ") : "All findings";
}

let autocompleteSeq = 0;

function collectionControl(label, value = "", attrs = {}) {
  const listId = `collection-options-${++autocompleteSeq}`;
  const input = textInput(value, {...attrs, list: listId, autocomplete: "off"});
  const choices = h("datalist", {id: listId});
  const wrapper = field(label, input);
  wrapper.append(choices);
  const setCollections = names => {
    const unique = [...new Set((names || []).filter(Boolean).map(String))].sort((a, b) => a.localeCompare(b));
    choices.replaceChildren(...unique.map(name => h("option", {value: name})));
  };
  setCollections(attrs.collections || []);
  return {field: wrapper, input, setCollections};
}

async function loadStoreSchema(storeId, sampleChunks = 0, force = false) {
  if (!storeId || storeId === "__all__") return null;
  const key = `${storeId}:${sampleChunks}`;
  if (force) delete state.schemas[key];
  if (!state.schemas[key]) {
    state.schemas[key] = await api(`/stores/${encodeURIComponent(storeId)}/schema?sample_chunks=${encodeURIComponent(sampleChunks)}`);
  }
  return state.schemas[key];
}

async function syncCollectionControl(storeId, control) {
  control.setCollections([]);
  if (!storeId || storeId === "__all__") return;
  try {
    const schema = await loadStoreSchema(storeId, 0);
    control.setCollections((schema.collections || []).map(c => c.name));
  } catch {
    control.setCollections([]);
  }
}

async function allKnownCollections() {
  const names = [];
  for (const store of state.stores || []) {
    try {
      const schema = await loadStoreSchema(store.store_id, 0);
      names.push(...((schema.collections || []).map(c => c.name)));
    } catch {}
  }
  return [...new Set(names)].sort((a, b) => a.localeCompare(b));
}

// A screen has one name, and it lives in `views`. Passing a different string
// here is how a tab and the page beneath it came to carry two different names:
// the label was renamed in one place and not the other. A view id resolves to
// the registry name; an explicit string is still allowed for sub-sections.
//
// The page header is where a screen names itself, once: its title (the page's
// only h1, and the focus target a route change lands on), one sentence, an
// optional scope picker, and at most one primary action. The top bar carries
// no second copy of the title. Facts and the "About this screen" disclosure
// come from pageIntro(), placed directly beneath.
let pageHeaderShown = false;

// A record's page (one store, one saved audit, one plan) passes `back`
// ({label, onclick, className}): one link above the title, back to the list
// the record sits in. Its title is the record's name, given as text or nodes;
// `titleClass` keeps a class older styles and tests know the heading by.
function pageHeader(titleOrView, desc, action, {scope = null, literal = false, back = null, titleClass = ""} = {}) {
  // `literal` for a title that is data (a store id), which must not be read
  // as a view id even when it happens to be one.
  const registered = literal || typeof titleOrView !== "string" ? null : views[titleOrView];
  const title = registered ? registered[0] : titleOrView;
  const description = desc === undefined && registered ? registered[1] : desc;
  pageHeaderShown = true;
  return h("header", {class: "page-head"},
    h("div", {class: "page-head-text"},
      back
        ? h("button", {class: `link page-back${back.className ? ` ${back.className}` : ""}`, type: "button",
                       onclick: back.onclick}, icon("back"), back.label)
        : "",
      h("h1", {id: "page-title", tabindex: "-1", class: titleClass || false}, title),
      description ? h("p", {class: "page-desc"}, description) : ""),
    scope || action
      ? h("div", {class: "page-head-actions"}, scope || "", action || "")
      : "");
}

// A screen that failed to render still gets its heading, so focus has somewhere to land and the page is named.
function ensurePageHeader(content, id) {
  if (pageHeaderShown) return;
  content.replaceChildren(pageHeader(id), ...Array.from(content.children || []));
}

// What each Compliance screen is for, in the terms of the job someone arrives
// with. `pageHeader` names the screen; this says what to do on it, what it
// holds right now, and where the next step lives. The palette reuses `purpose`
// as its hint, so searching for a task finds the screen that does it.
const SCREEN_INTENTS = {
  frameworks: {
    glyph: "layers",
    purpose: "Reference for the laws and standards this pack maps: which obligations each one places on a vector store, what the automatic checks can see for each, and which documents a person still has to supply.",
    terms: ["framework", "obligation", "criterion", "control"],
    uses: ["Read what a regulation requires before you run an assessment",
           "See which automated checks and manual artifacts a criterion needs",
           "Jump from a framework to its criteria, templates, or policies"],
  },
  criteria: {
    glyph: "check",
    purpose: "See where one store stands on each obligation, using its latest saved assessment. Each criterion keeps four things apart: whether it applies, what the checks saw, whether its documents were accepted, and what a named reviewer decided.",
    uses: [COMPLIANCE_COPY.criteria.steps2[0],
           "Answer this store's questions once, and add documents for review",
           "Export a criterion's position with its caveats attached"],
  },
  evidence: {
    glyph: "file",
    purpose: "The document register. A document is a file you keep and add here; its state says whether the file can be relied on. A review is a named reviewer's decision that one document does or does not meet one need of one criterion. The same file can be accepted for one obligation and rejected for another.",
    terms: ["document", "evidenceStatus"],
    uses: ["Add a document with its store, period, and content hash",
           "Confirm its integrity and make it ready for review, then send it for a criterion",
           "Decide open reviews, with a reason, and spot acceptances that no longer count"],
  },
  exceptions: {
    glyph: "key",
    purpose: "Gaps someone chose to accept for now. An exception never closes a gap: it names the criterion and store, carries a reason, needs an approver other than the requester, and ends on a set date.",
    terms: ["exception"],
    uses: ["Request one for a gap while a fix is under way",
           "Approve, with a reason, or revoke an exception",
           "See which exceptions have ended and reopened their gap"],
  },
  dsar: {
    glyph: "user",
    purpose: COMPLIANCE_COPY.dsar.purpose,
    uses: ["Open a request for a person: an email, a name, or an account id",
           "Check how many chunks matched, per store, before deleting anything",
           "Keep a record for the GDPR Art. 17 and CCPA \u00a71798.105 erasure criteria"],
  },
  policies: {
    glyph: "sliders",
    purpose: "The rules in force. A policy points a detection rule at a store or collection and names what a matching finding needs. Only a policy turns a finding into something you must act on.",
    terms: ["policy", "template"],
    uses: ["Enable, disable, or delete a configured policy",
           "See which framework a policy came from, and at what severity",
           "Create a policy from a template or write a custom rule"],
  },
  templates: {
    glyph: "layers",
    purpose: "Ready-made rules, by framework. A template is a detection rule with its source, its questions, and what it can and cannot show. Test one against recent findings, then turn it into a policy.",
    terms: ["template", "policy"],
    uses: ["Filter by framework, category, severity, or required label",
           "Inspect what a rule detects, and what it cannot establish",
           "Customise a template into a scoped policy"],
  },
  findings: {
    glyph: "alert",
    purpose: "Triage what assessments observed. A finding is an observation: a detector match, a probe result, a configuration fact. It is not a verdict, it does not establish compliance or a breach, and a store whose latest audit had partial coverage can hold more than is listed. Its case records what your team decided, step by step:",
    uses: [],
  },
  falsepositives: {
    glyph: "funnel",
    purpose: "Calibration for known-benign matches. An allow-list rule describes a pattern that is benign everywhere it applies; a suppression silences one finding fingerprint until a date. Both tag findings; neither hides them.",
    terms: ["suppression"],
    uses: ["Check which built-in allow-list rules apply to a store",
           "See who suppressed a finding, why, and when it comes back",
           "Tell a permanent calibration from a time-boxed one"],
  },
  crypto: {
    glyph: "lock",
    purpose: "What one store's saved audit could observe about encryption and data protection, one control layer at a time. Layers are never merged into one verdict, and a property the store does not expose is shown as not observable, never as a failure.",
    uses: ["Choose a store; its most recent saved audit is read, never a fresh scan",
           "Read each layer: transport, storage encryption, field and data level, retrieval",
           "See which regulations the observations inform, and what evidence fills the gaps"],
  },
};

// What sits under a page header: the screen's counts, inline, and a closed
// "About this screen" disclosure holding its purpose, the steps or uses, any
// fact that is not a count, and the links onward. Nothing that used to be in
// the intro strip is dropped; it is folded away. Facts are counts or short
// values, never a percentage, and only counts stay in view.
function isCountFact(value) {
  // A number, or "?"/"Unknown" standing for a count that could not be read.
  // A dash for "not chosen" is not a count; it goes in About with the rest.
  return /^(?:[\d.,\u202f\u00a0 ]+|\?|Unknown)$/.test(String(value ?? "").trim());
}

// `explain` is a screen's own longer explanation (how a criterion is judged),
// folded into the same disclosure after the purpose.
function pageIntro(viewId, {facts = [], actions = [], steps = null, explain = null} = {}) {
  const intent = SCREEN_INTENTS[viewId];
  if (!intent) return "";
  const list = steps || intent.uses || [];
  const counts = facts.filter(([, value]) => isCountFact(value));
  const others = facts.filter(([, value]) => !isCountFact(value));
  const factDl = (items, className) => factList(items, {className, itemClass: "page-fact",
                                                       valueClass: "page-fact-v", noteClass: "page-fact-n"});
  return h("div", {class: `page-meta intro-${viewId}`},
    counts.length ? factDl(counts, "page-facts") : "",
    h("details", {class: "about"},
      h("summary", {}, icon("info"), "About this screen"),
      h("div", {class: "about-body"},
        h("p", {class: "about-purpose"}, intent.purpose),
        explain || "",
        list.length
          ? h("ol", {class: `intro-uses${steps ? " intro-steps" : ""}`},
              list.map(text => h("li", {}, text)))
          : "",
        (intent.terms || []).length
          ? h("div", {class: "about-terms"}, h("div", {class: "metric-k"}, "Words on this screen"), termList(intent.terms))
          : "",
        others.length ? factDl(others, "page-facts page-facts-other") : "",
        actions.length ? h("div", {class: "about-links"}, actions) : "")));
}

// A link onward from "About this screen". Never a primary button: the page
// header holds the screen's one primary action.
function introAction(label, glyph, onclick) {
  return h("button", {class: "link about-link", type: "button", onclick},
    icon(glyph), label);
}

// Five data states, kept distinct because they mean different things: an empty
// result, an unmeasured one, a fetch that failed, a partial answer, and work in
// progress. Rendering them all as the same grey line is how "we did not look"
// comes to read as "we looked and found nothing".
const STATE_GLYPH = {
  empty: "archive", unknown: "sev-unknown", unavailable: "sev-medium",
  error: "sev-critical", partial: "sev-medium", loading: "clock",
};

// A caveat or a one-line fact about what is on screen: a compact note, icon
// and text, left-aligned. It is not an empty state (those keep their own
// centred shape) and it is not announced: a static note read aloud on every
// page load is noise. Pass {live: true} only when the line reports the outcome
// of something the reader just did.
const NOTE_GLYPH = {info: "info", ok: "sev-ok", medium: "sev-medium", high: "sev-high",
                    critical: "sev-critical", low: "sev-low"};

function statusLine(text, kind = "info", {live = false} = {}) {
  const glyph = NOTE_GLYPH[kind] || STATE_GLYPH[kind] || "sev-medium";
  const attrs = {class: `note note-${kind}`};
  // An empty note (an optional API caveat that was absent) takes no space.
  if (text == null || text === "") attrs.hidden = true;
  if (live) attrs.role = kind === "error" ? "alert" : "status";
  return h("p", attrs, h("span", {class: `note-icon sev-${kind}`}, icon(glyph)),
    h("span", {class: "note-text"}, text));
}

function emptyState(text, {action, actionLabel} = {}) {
  return h("div", {class: "state state-empty", role: "status"},
    icon(STATE_GLYPH.empty), h("p", {}, text),
    action ? h("button", {class: "btn small", type: "button", onclick: action}, actionLabel || "Get started") : "");
}

function unknownState(text, detail = "") {
  return h("div", {class: "state state-unknown", role: "status"},
    icon(STATE_GLYPH.unknown), h("p", {}, text),
    detail ? h("p", {class: "sub"}, detail) : "");
}

function unavailableState(text, detail = "") {
  return h("div", {class: "state state-unavailable", role: "status"},
    icon(STATE_GLYPH.unavailable), h("p", {}, text),
    detail ? h("p", {class: "sub"}, detail) : "");
}

// role="alert" because a failed request is interrupting something the user
// asked for, unlike an empty list they can simply read.
function errorState(message, onRetry) {
  return h("div", {class: "state state-error", role: "alert"},
    icon(STATE_GLYPH.error), h("p", {class: "error-text"}, message),
    onRetry ? h("button", {class: "btn small", type: "button", onclick: onRetry}, icon("refresh"), "Retry") : "");
}

function loadingState(text = "Loading...") {
  return h("div", {class: "state state-loading", role: "status", "aria-live": "polite"},
    h("span", {class: "skeleton-line"}), h("span", {class: "skeleton-line short"}),
    h("span", {class: "sr-only"}, text));
}

async function loadCore() {
  state.policiesError = "";
  try {
    state.stores = (await api("/admin/stores")).stores || [];
    state.admin = true;
  } catch (e) {
    if (e.status === 409) {
      state.admin = false;
      state.stores = (await api("/stores")).stores || [];
    } else {
      state.stores = [];
      throw e;
    }
  }
  try {
    state.templates = (await api("/admin/policy-templates")).templates || [];
  } catch {
    state.templates = [];
  }
  if (state.admin) {
    try {
      state.policies = (await api("/admin/policies")).policies || [];
    } catch (e) {
      state.policies = [];
      state.policiesError = unavailableReason(e);
    }
  } else {
    state.policiesError = "Policy administration is disabled.";
  }
}

let shellListening = false;

// The palette's shortcut as this platform writes it. "/" opens it too, but a
// search field that shows a modifier shortcut is the convention people know.
function paletteShortcutHint() {
  let platform = "";
  try {
    const nav = typeof navigator === "undefined" ? null : navigator;
    platform = nav?.userAgentData?.platform || nav?.platform || "";
  } catch { platform = ""; }
  return /mac|iphone|ipad/i.test(platform) ? "⌘K" : "Ctrl K";
}

function buildShell() {
  root.replaceChildren(
    h("div", {class: "app"},
      // First in the tab order: straight past the navigation to the page's
      // heading. A button, because the hash belongs to the router.
      h("button", {class: "skip-link", type: "button", onclick: skipToContent}, "Skip to content"),
      // Behind the phone drawer; tapping it closes the drawer. Before the
      // sidebar in the document, so at the same level the drawer paints over it.
      h("div", {class: "side-backdrop", id: "side-backdrop", hidden: true,
                onclick: () => setDrawer(false)}),
      h("aside", {class: "side", id: "side"},
        h("div", {class: "brand"},
          h("img", {class: "logo", src: "/static/assets/vecshield-mark.svg", alt: "", width: "40", height: "40"}),
          h("div", {}, h("strong", {}, "VecShield"), h("span", {}, "Privacy & Compliance")),
          h("button", {class: "icon-btn side-close", type: "button", "aria-label": "Close navigation",
                       title: "Close navigation", onclick: () => setDrawer(false)}, icon("close"))),
        h("nav", {id: "nav", "aria-label": "Areas"}),
        h("div", {class: "side-foot"},
          h("div", {class: "nav-head"}, "System"),
          h("nav", {id: "nav-system", "aria-label": "System"}),
          h("div", {id: "version-foot"}, "Version loading..."))),
      h("main", {class: "main", id: "main"},
        // One row. The page names itself in its own header below, so the bar
        // carries no second title; it holds search and the session controls.
        // Below 900px those controls fold into the "More" menu so the bar
        // stays one short row on a phone.
        h("div", {class: "top", id: "top"},
          h("button", {class: "icon-btn menu", id: "menu-btn", type: "button", "aria-expanded": "false",
                       "aria-controls": "side", "aria-label": "Open navigation",
                       onclick: () => setDrawer(!drawerOpen())}, icon("menu")),
          h("span", {class: "top-brand"},
            h("img", {class: "top-logo", src: "/static/assets/vecshield-mark.svg", alt: "", width: "28", height: "28"}),
            h("span", {class: "top-brand-name"}, "VecShield")),
          h("button", {class: "btn small palette-btn", type: "button", id: "palette-btn",
                       onclick: () => openPalette(),
                       "aria-label": "Search and jump to anything"},
            icon("search"), h("span", {class: "palette-hint"}, "Search"),
            h("kbd", {"aria-hidden": "true"}, paletteShortcutHint())),
          h("button", {class: "icon-btn help-btn", id: "help-btn", type: "button", title: "Docs",
                       "aria-label": "Docs: what the console does and what each screen answers",
                       onclick: () => goTo("docs")}, icon("help")),
          h("button", {class: "icon-btn more-btn", id: "more-btn", type: "button", "aria-expanded": "false",
                       "aria-controls": "top-actions",
                       "aria-label": state.auth.login_enabled ? "Status, account and theme" : "Status, token and theme",
                       onclick: () => setTopMenu(!topMenuOpen())}, icon("more")),
          h("div", {class: "top-actions", id: "top-actions"},
            h("span", {class: "health"}, "Checking..."),
            // Signed-in deployments show who is signed in; token deployments
            // keep the bearer token field.
            state.auth.login_enabled
              ? accountMenu()
              : h("input", {class: "token", type: "password", placeholder: "Bearer token", value: state.token, "aria-label": "Bearer token", oninput: e => {
                  state.token = e.target.value;
                  sessionStorage.setItem("vecshield_token", state.token);
                }, onchange: async () => {
                  // A new token is a new principal: what it may do is re-read,
                  // and the console redrawn with the screens and controls that fit it.
                  await loadSession();
                  enterConsole();
                }}),
            // With sign-in off there is no account menu; Settings is still
            // where this browser's preferences live.
            state.auth.login_enabled ? "" : h("button", {class: "icon-btn", id: "settings-btn", type: "button",
              title: "Settings", "aria-label": "Settings", onclick: () => goTo("settings")}, icon("sliders")),
            h("button", {class: "icon-btn", id: "theme-toggle", title: "Toggle theme", "aria-label": "Toggle theme", onclick: toggleTheme}, icon("moon")))),
        h("div", {class: "view-chrome", id: "view-chrome"}),
        h("div", {class: "content", id: "content"}),
        // Route changes replace the whole content area; without this a screen
        // reader is told nothing at all about what just happened.
        h("div", {id: "live-region", class: "sr-only", role: "status", "aria-live": "polite"}, ""))));
  buildNav();
  syncThemeIcon();
  // The shell is rebuilt after signing in; its document listeners are not.
  if (shellListening) return;
  shellListening = true;
  document.addEventListener("click", event => {
    const target = event?.target;
    if (openRowMenu && !target?.closest?.(".menu-wrap")) closeRowMenu();
    // A tap outside the More menu closes it, as it closes any other menu.
    if (topMenuOpen() && !target?.closest?.("#top-actions, #more-btn")) setTopMenu(false);
    // A tip opened by a tap closes on a tap anywhere else, which a touch
    // screen does not always treat as leaving the glyph.
    const tip = document.activeElement;
    if (tip?.classList?.contains("tip") && !tip.contains?.(target)) tip.blur?.();
  });
  // A scroll inside an open menu is the menu's own; any other scroll would
  // leave the menu floating away from its row, so it closes.
  window.addEventListener?.("scroll", event => {
    if (!event?.target?.closest?.(".menu-pop")) closeRowMenu();
  }, true);
  // Widening past the phone layout turns the drawer back into the sidebar;
  // an open drawer would otherwise leave its backdrop and an inert page.
  globalThis.matchMedia?.("(min-width: 901px)")?.addEventListener?.("change", event => {
    if (event?.matches && drawerOpen()) setDrawer(false, {restoreFocus: false});
  });
  document.addEventListener("keydown", event => {
    if (event?.key === "Escape" && drawerOpen()) {
      setDrawer(false);
      return;
    }
    if (event?.key === "Escape" && topMenuOpen()) {
      setTopMenu(false);
      document.getElementById("more-btn")?.focus?.();
      return;
    }
    // Two ways in, because "/" is what people reach for in a console and
    // Cmd/Ctrl-K is what they reach for everywhere else.
    const inField = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
    if ((event?.key === "k" && (event.metaKey || event.ctrlKey)) ||
        (event?.key === "/" && !inField && !openDialog)) {
      event.preventDefault?.();
      openPalette();
    }
  });
}

// ---------------------------------------------------------------- palette ---
// With six areas, a System group and two dozen screens, typing where you want
// to go beats hunting for it. Entries are destinations and actions, not search
// results: every one of them does something when chosen.

// The last few places this tab visited, for the palette's "Recent" group.
// Session storage, so it ends with the tab; sign-out forgets it too.
const RECENT_KEY = "vecshield_recent";
const RECENT_MAX = 5;

function readRecent() {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(RECENT_KEY) || "[]");
    return Array.isArray(parsed)
      ? parsed.filter(r => r && typeof r.view === "string" && views[r.view])
      : [];
  } catch { return []; }
}

function rememberRecent(view, params) {
  const query = params?.toString?.() || "";
  const next = [{view, query}, ...readRecent().filter(r => r.view !== view || r.query !== query)]
    .slice(0, RECENT_MAX);
  try { sessionStorage.setItem(RECENT_KEY, JSON.stringify(next)); } catch { /* private mode */ }
}

// Recent places as palette entries, newest first, leaving out the page the
// reader is on and any screen their role no longer has.
function recentPaletteEntries() {
  const here = renderedRoute;
  return readRecent()
    .filter(r => `${r.view}?${r.query}` !== here && viewAvailable(r.view))
    .map(({view, query}) => {
      const [label, sub, group] = views[view];
      const scope = new URLSearchParams(query);
      const store = scope.get("store");
      return {
        label: `${group === label ? label : `${group}: ${label}`}${store ? ` · ${store}` : ""}`,
        hint: sub, glyph: navIcon(view), group: "Recent",
        run: () => { location.hash = `#/${view}${query ? `?${query}` : ""}`; },
      };
    });
}

function paletteEntries() {
  const entries = [];
  for (const [name, glyph, blurb, members] of AREAS) {
    entries.push({
      label: name, hint: blurb, glyph, group: "Areas",
      run: () => goTo(members[0]),
    });
  }
  for (const [id, [label, sub, group]] of Object.entries(views)) {
    if (!viewAvailable(id)) continue;
    entries.push({
      label: `${group}: ${label}`, hint: sub, glyph: navIcon(id), group: "Screens",
      // The purpose text is searchable, so "erase" finds Privacy and "tolerate"
      // finds Exceptions, without being the line shown under the name.
      keywords: SCREEN_INTENTS[id]?.purpose || "",
      run: () => goTo(id),
    });
  }
  // Once a screen has loaded the criterion pack, each framework is a destination
  // of its own: its criteria, and the templates and policies derived from it.
  for (const framework of (state.pack?.pack?.frameworks || [])) {
    entries.push({
      label: `Frameworks: ${framework}`,
      hint: `${framework} obligations, the checks and evidence each needs`,
      glyph: "layers", group: "Screens",
      run: () => goTo("frameworks", {framework}),
    });
    entries.push({
      label: `Criteria: ${framework}`,
      hint: `Evaluate a store's saved audit against ${framework} criteria`,
      glyph: "check", group: "Screens",
      run: () => goTo("criteria", {framework}),
    });
  }
  if (state.auth.login_enabled && state.auth.user) {
    if (ownsSession()) {
      entries.push({label: "Change password", hint: `Signed in as ${state.auth.user.username || "you"}`,
                    glyph: "key", group: "Account", run: () => goTo("settings", {focus: "password"})});
      entries.push({label: "Your sessions", hint: "See where you are signed in, and sign other browsers out",
                    glyph: "user", group: "Account", run: () => goTo("settings")});
    }
    entries.push({label: "Sign out", hint: "End this session on this browser",
                  glyph: "back", group: "Account", run: () => signOut()});
  }
  for (const store of state.stores || []) {
    entries.push({
      label: `Open ${store.store_id}`, hint: `${store.kind} store — reachability, collections and next steps`,
      glyph: "db", group: "Stores",
      run: () => goTo("stores", {store: store.store_id}),
    });
    entries.push({
      label: store.store_id, hint: `${store.kind} store — open its schema`,
      glyph: "db", group: "Stores",
      run: () => goTo("schema", {store: store.store_id}),
    });
    if (can("operator")) entries.push({
      label: `Assess ${store.store_id}`, hint: "Open the assessment page scoped to this store",
      glyph: "shield", group: "Stores",
      run: () => goTo("assess", {store: store.store_id}),
    });
    entries.push({
      label: `Crypto posture of ${store.store_id}`,
      hint: "Encryption and data protection its saved audit observed",
      glyph: "lock", group: "Stores",
      run: () => goTo("crypto", {store: store.store_id}),
    });
  }
  return entries;
}

// A name that contains the query outranks a hint that does, which outranks a
// subsequence match; ties keep the registry order. Without this, "gdpr" matched
// every long description by subsequence and buried the GDPR entries.
function paletteScore(entry, query) {
  const tokens = normalizeText(query).split(" ").filter(Boolean);
  if (!tokens.length) return 0;
  const label = normalizeText(entry.label);
  const hint = normalizeText(`${entry.hint || ""} ${entry.group || ""} ${entry.keywords || ""}`);
  let score = 0;
  for (const token of tokens) {
    if (label.includes(token)) score += label.startsWith(token) ? 0 : 1;
    else if (hint.includes(token)) score += 3;
    else if (isSubsequence(token, label)) score += 6;
    else return null;
  }
  return score;
}

function rankPaletteEntries(entries, query) {
  return entries
    .map((entry, index) => ({entry, index, score: paletteScore(entry, query)}))
    .filter(x => x.score != null)
    .sort((a, b) => a.score - b.score || a.index - b.index)
    .map(x => x.entry);
}

function openPalette() {
  const entries = paletteEntries();
  // Shown only before anything is typed; a query searches destinations.
  const recent = recentPaletteEntries();
  const input = textInput("", {placeholder: "Jump to an area, screen, or store", "aria-label": "Search"});
  const list = h("div", {class: "palette-list", role: "listbox"});
  const count = h("p", {class: "sub"}, "");
  let visible = [];
  let cursor = 0;

  function choose(entry) {
    closeModal();
    entry.run();
  }

  function draw() {
    const matches = rankPaletteEntries(entries, input.value).slice(0, 40);
    visible = input.value.trim() ? matches : [...recent, ...matches];
    cursor = Math.min(cursor, Math.max(0, visible.length - 1));
    // The count is of destinations; the recent rows repeat some of them.
    count.textContent = `${number(matches.length)} of ${number(entries.length)}`;
    // The grid lives on an inner span, not on the <button>: a button that is
    // itself a grid container is sized to its min-height in Chrome and the
    // second row collapses to nothing, so every hint spilled onto the row below.
    list.replaceChildren(...(visible.length
      ? visible.map((entry, index) => h("button", {
          class: `palette-item${index === cursor ? " palette-active" : ""}`,
          type: "button", role: "option", "aria-selected": index === cursor ? "true" : "false",
          dataset: {group: entry.group},
          onclick: () => choose(entry),
        },
        h("span", {class: "palette-row"},
          h("span", {class: "palette-glyph"}, icon(entry.glyph)),
          h("span", {class: "palette-text"},
            h("span", {class: "palette-label"}, entry.label),
            h("span", {class: "palette-hint sub"}, entry.hint)),
          h("span", {class: "palette-group"}, entry.group),
          h("kbd", {class: "palette-enter", "aria-hidden": "true"}, "\u21B5"))))
      : [emptyState("Nothing matches that.")]));
    // Keep the active row in view while the arrow keys move it.
    list.children[cursor]?.scrollIntoView?.({block: "nearest"});
  }

  input.addEventListener("input", draw);
  input.addEventListener("keydown", event => {
    if (event?.key === "ArrowDown" || event?.key === "ArrowUp") {
      event.preventDefault?.();
      if (!visible.length) return;
      cursor = (cursor + (event.key === "ArrowDown" ? 1 : visible.length - 1)) % visible.length;
      draw();
    } else if (event?.key === "Enter" && visible.length) {
      event.preventDefault?.();
      choose(visible[cursor]);
    }
  });

  draw();
  const backdrop = modal("Go to", h("div", {class: "palette"},
    h("div", {class: "search-field"}, icon("search"), input),
    h("div", {class: "palette-meta"},
      count,
      h("span", {class: "palette-keys", "aria-hidden": "true"},
        h("kbd", {}, "\u2191"), h("kbd", {}, "\u2193"), " move ",
        h("kbd", {}, "\u21B5"), " open ",
        h("kbd", {}, "esc"), " close")),
    list), null, "Close");
  // A command palette sits high and narrow; the default dialog is a form.
  backdrop?.querySelector?.(".modal")?.classList?.add("modal-palette");
  input.focus?.();
  return {input, list, count};
}

// The narrow-screen menu that holds health, token and theme. On a wide screen
// the same controls sit in the bar and this state has no visible effect.
function topMenuOpen() {
  return Boolean(document.getElementById("top")?.classList?.contains("menu-open"));
}

function setTopMenu(open) {
  const top = document.getElementById("top");
  const button = document.getElementById("more-btn");
  top?.classList?.toggle("menu-open", open);
  button?.setAttribute("aria-expanded", String(open));
  if (open) focusableWithin(document.getElementById("top-actions"))[0]?.focus?.();
}

function drawerOpen() {
  return Boolean(document.getElementById("side")?.classList?.contains("open"));
}

// While the drawer or a dialog is open, the page under it stays put: on a
// phone a swipe on the backdrop scrolled the page behind. The stylesheet
// applies the class below 900px only.
function syncScrollLock() {
  document.documentElement?.classList?.toggle?.("is-locked", Boolean(openDialog) || drawerOpen());
}

// The phone drawer. While it is open the page behind it is inert, so neither
// Tab nor a screen reader wanders into content the backdrop covers. Every way
// of closing it (Escape, the backdrop, its close button, choosing a screen, a
// route change, the window widening past 900px) comes through here, so the
// page is never left inert.
function setDrawer(open, {restoreFocus = true} = {}) {
  const side = document.getElementById("side");
  const button = document.getElementById("menu-btn");
  const backdrop = document.getElementById("side-backdrop");
  const main = document.getElementById("main");
  side?.classList?.toggle("open", open);
  button?.setAttribute("aria-expanded", String(open));
  if (open) {
    backdrop?.removeAttribute?.("hidden");
    main?.setAttribute?.("inert", "");
    focusableWithin(side)[0]?.focus?.();
  } else {
    backdrop?.setAttribute?.("hidden", "");
    // Before focus moves: an inert trigger cannot take it.
    main?.removeAttribute?.("inert");
    if (restoreFocus) button?.focus?.();
  }
  syncScrollLock();
}

function skipToContent() {
  if (drawerOpen()) setDrawer(false, {restoreFocus: false});
  document.getElementById("page-title")?.focus?.();
}

function announce(message) {
  const region = document.getElementById("live-region");
  if (region) region.textContent = message;
}

function buildNav() {
  const nav = document.getElementById("nav");
  nav.replaceChildren();
  const system = document.getElementById("nav-system");
  system?.replaceChildren?.();
  const go = view => () => {
    goTo(view);
    if (drawerOpen()) setDrawer(false);
  };
  for (const [name, glyph, , members, placement] of AREAS) {
    if (placement === "main") {
      nav.append(h("button", {
        class: "nav-btn", type: "button", dataset: {area: name, view: members[0]},
        onclick: go(members[0]),
      }, icon(glyph), name));
    } else if (placement === "system" && system) {
      // Each system screen is its own quiet link; there are four (Users only
      // where sign-in is on), and none is a daily destination.
      for (const id of members.filter(viewAvailable)) {
        system.append(h("button", {class: "nav-btn nav-sys", type: "button",
                                   dataset: {area: name, view: id}, onclick: go(id)},
          icon(navIcon(id)), views[id][0]));
      }
    }
  }
}

// Tabs within an area. The area is the destination; the tab is where you are
// inside it, and it travels in the URL like everything else.
// Screens whose content is one store's. Moving between their tabs keeps the
// store the reader chose; Estate → Crypto → Schema used to drop it.
const STORE_SCOPED_VIEWS = new Set(["schema", "crypto", "assess", "history", "findings",
                                    "actions", "criteria"]);

function carriedParams(targetView) {
  const store = param("store");
  return store && STORE_SCOPED_VIEWS.has(targetView) ? {store} : {};
}

// The last store the reader chose, for this browser session. A screen that
// uses it says so; it is never picked silently, and never "the first store".
function rememberStore(storeId) {
  if (!storeId || storeId === "__all__") return;
  try { sessionStorage.setItem("vecshield_store", storeId); } catch { /* private mode */ }
}

function lastUsedStore() {
  let id = "";
  try { id = sessionStorage.getItem("vecshield_store") || ""; } catch { id = ""; }
  return id && (state.stores || []).some(s => s.store_id === id) ? id : "";
}

function scopedStore() {
  const explicit = param("store");
  if (explicit) return {id: explicit, remembered: false};
  const last = lastUsedStore();
  return {id: last, remembered: Boolean(last)};
}

function rememberedStoreNote(scope) {
  return scope.remembered
    ? statusLine(`Showing ${scope.id}, the store you last used. Choose another to change it.`, "info")
    : "";
}

// On a record the breadcrumb's last step is the page; the tab it sits under is
// only the current section, so it says "true" rather than claiming the page.
function areaTabs(currentView, {detail = false} = {}) {
  const area = areaOf(currentView);
  const tabsFor = area ? area[3].filter(id => !SUBVIEW_PARENT[id] && viewAvailable(id)) : [];
  if (tabsFor.length < 2) return "";
  const currentTab = SUBVIEW_PARENT[currentView] || currentView;
  return h("nav", {class: "tabs", "aria-label": `${area[0]} sections`},
    tabsFor.map(id => {
      const [label] = views[id];
      const active = id === currentTab;
      return h("button", {
        class: `tab${active ? " tab-active" : ""}`, type: "button",
        "aria-current": active ? (detail ? "true" : "page") : false,
        onclick: () => goTo(id, carriedParams(id)),
      }, label);
    }));
}

// A screen with a view inside it (Criteria and Frameworks, Policies and
// Templates) offers both as a two-way switch. History and Runs are the
// exception: their pages carry historySwitch, which also chooses between
// History's two lists, so a chrome switch above it would be a second row.
function subviewSwitch(currentView) {
  const parent = SUBVIEW_PARENT[currentView] || currentView;
  if (parent === "history") return "";
  const kids = subviewsOf(parent);
  if (!kids.length) return "";
  return segmented({label: `${views[parent][0]} views`, className: "subviews",
                    options: [parent, ...kids].map(id => [id, views[id][0]]), value: currentView,
                    navigates: true, onPick: id => goTo(id, carriedParams(id))});
}

// One record inside a screen: a store, a saved audit, a plan. The address
// keeps its query form (`#/history?audit=a1`), and this table is what makes
// that a level of its own: the breadcrumb's last step, the announcement, the
// window title, and where "back" goes. Each entry is [param, label, options],
// checked in the order the screen's render checks them; `keep` carries params
// to the list, `parent` names the list's own params, and `when` says the
// param only opens the record in that state (the approval queue outranks a
// plan in the address). `findings?finding=` is a drawer over the list, so it
// is not here.
const DETAIL_PARAMS = {
  stores: [["store", v => v]],
  schema: [["collection", v => v, {keep: ["store", "sample"]}]],
  history: [["audit", v => recordLabel("Audit", v), {keep: ["store"]}],
            ["scan", v => recordLabel("Scan", v), {parent: {list: "scans"}}]],
  actions: [["plan", v => recordLabel("Plan", v), {parent: () => actionsQueueParams, when: notApprovalQueue}],
            ["fix", () => "Fix", {parent: () => actionsQueueParams, when: notApprovalQueue}],
            ["finding", () => "Fix", {parent: () => actionsQueueParams, when: notApprovalQueue}]],
  criteria: [["answers", () => "Questions", {keep: ["store", "framework"]}]],
  dsar: [["request", v => recordLabel("Request", v)]],
};

function notApprovalQueue(params) {
  return params.get("queue") !== "approval";
}

// A record's name: "Audit a1", but an id that already says what it is
// ("audit-8d47…", "plan-3f0c…") is not prefixed a second time.
function recordLabel(kind, id) {
  return String(id).toLowerCase().startsWith(`${kind.toLowerCase()}-`) ? String(id) : `${kind} ${id}`;
}

// The same name as a page title, with the id in monospace.
function recordTitle(kind, id) {
  const mono = h("span", {class: "mono"}, id);
  return recordLabel(kind, id) === String(id) ? mono : [`${kind} `, mono];
}

// The record a route opens, or null on a list: {param, value, label, parent},
// where `parent` is the params that lead back to the list it came from.
function detailOf(view, params = readRoute().params) {
  const query = typeof params === "string" ? new URLSearchParams(params) : params;
  for (const [name, label, options = {}] of DETAIL_PARAMS[view] || []) {
    const value = query.get(name);
    if (!value || (options.when && !options.when(query))) continue;
    const parent = {...(typeof options.parent === "function" ? options.parent() : options.parent || {})};
    for (const key of options.keep || []) {
      if (query.get(key)) parent[key] = query.get(key);
    }
    return {param: name, value, label: label(value), parent};
  }
  return null;
}

// Back to the list a record was opened from: the breadcrumb's middle step and
// each record page's back link both go here.
function climbOut(view) {
  const detail = detailOf(view);
  goTo(view, detail ? detail.parent : {});
}

// Where you are, when the area tabs cannot say it alone: on a record, the
// trail is area › screen › record, and each step above the record goes there.
// A list needs no trail (its tab is current), so route() shows this only on a
// record; called for a list it still names the area and the screen.
function breadcrumbs(currentView, params = readRoute().params) {
  const area = areaOf(currentView);
  if (!area) return "";
  const [areaName, , , members] = area;
  const detail = detailOf(currentView, params);
  const trail = [h("li", {}, h("button", {
    class: "crumb", type: "button", onclick: () => goTo(members[0]),
  }, areaName))];
  if (detail) {
    trail.push(h("li", {}, h("button", {class: "crumb", type: "button",
                                        onclick: () => goTo(currentView, detail.parent)},
      views[currentView][0])));
    trail.push(h("li", {}, h("span", {class: "crumb crumb-current", "aria-current": "page"},
      detail.label)));
  } else if (members.length > 1 || currentView !== members[0]) {
    trail.push(h("li", {}, h("span", {class: "crumb crumb-current", "aria-current": "page"},
      views[currentView][0])));
  }
  return h("nav", {class: "breadcrumbs", "aria-label": "Breadcrumb"}, h("ol", {}, trail));
}


function navIcon(id) {
  return ({
    overview: "grid", stores: "db", schema: "list", assess: "shield", ingest: "funnel",
    policies: "sliders", templates: "layers", falsepositives: "funnel",
    runtime: "alert", detectors: "sliders", alerting: "bell", dsar: "user",
    jobs: "clock", history: "archive", audit: "list", status: "list",
    findings: "alert", criteria: "check", frameworks: "layers", docs: "file",
    evidence: "file", exceptions: "key", crypto: "lock", users: "users", settings: "sliders",
  })[id] || "grid";
}


// ---------------------------------------------------------------- routing ---
// The hash carries the view *and* its state: `#/assess?store=prod&job=a1f2`.
// Anything a user can see should be something they can send to a colleague, so
// selections, filters, and the run being watched all live here rather than in a
// closure that dies on reload.

// Links people already hold keep resolving. Every screen kept its view id
// through the re-parenting, and these cover the names that did move.
const LEGACY_VIEWS = {
  scans: "assess",
  audits: "assess",
  archive: "history",
  // 2026-10-06: the Run and Archive tabs became New assessment and History.
  "new-assessment": "assess",
  runs: "jobs",
  "background-jobs": "jobs",
  "false-positives": "falsepositives",
  "policy-templates": "templates",
  "audit-log": "audit",
  "runtime-alerts": "runtime",
  "privacy-requests": "dsar",
  "schema-explorer": "schema",
};

function resolveView(id) {
  if (views[id]) return id;
  if (LEGACY_VIEWS[id]) return LEGACY_VIEWS[id];
  return "overview";
}

function readRoute() {
  const raw = location.hash.replace(/^#\/?/, "");
  const cut = raw.indexOf("?");
  const id = cut === -1 ? raw : raw.slice(0, cut);
  return {
    view: resolveView(id),
    params: new URLSearchParams(cut === -1 ? "" : raw.slice(cut + 1)),
  };
}

function currentView() {
  return readRoute().view;
}

function param(name, fallback = "") {
  const value = readRoute().params.get(name);
  return value == null ? fallback : value;
}

let renderedRoute = null;

// Writing params must not tear the page down: the view already reflects the
// change that triggered the write.
function setParams(changes, {replace = true} = {}) {
  if (changes.store) rememberStore(changes.store);
  const {view, params} = readRoute();
  for (const [key, value] of Object.entries(changes)) {
    if (value == null || value === "") params.delete(key);
    else params.set(key, String(value));
  }
  const query = params.toString();
  const next = `#/${view}${query ? `?${query}` : ""}`;
  if (location.hash === next) return;
  if (replace) renderedRoute = `${view}?${query}`;
  location.hash = next;
}

function goTo(view, params = {}) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value != null && value !== "") query.set(key, String(value));
  }
  const suffix = query.toString();
  location.hash = `#/${view}${suffix ? `?${suffix}` : ""}`;
}

// `route()` runs for two reasons: the hash changed (the browser passes the
// hashchange event), or code asked for the screen to be redrawn after changing
// something (no argument). Only the first can be a param write we made
// ourselves; skipping the second left a list stale after adding to it.
async function route(event) {
  // An account screen owns the page; the hash waits for it, and is where the
  // reader lands once they are signed in.
  if (state.authScreen) return;
  const {view: id, params} = readRoute();
  rememberStore(params.get("store"));
  const signature = `${id}?${params.toString()}`;
  // A param write we made ourselves is already on screen.
  if (event?.type === "hashchange" && signature === renderedRoute) return;
  // Navigation takes every dialog with it: one opened on the previous page
  // must not sit over this one. A redraw of the same page leaves them be.
  const navigated = signature !== renderedRoute;
  // Unsaved edits on the page being left: put the address back and ask. The
  // restored hash matches renderedRoute, so its own hashchange is a no-op.
  if (navigated && leaveGuard && renderedRoute && leaveGuard.dirty()) {
    const target = location.hash;
    location.hash = `#/${renderedRoute.replace(/\?$/, "")}`;
    confirmLeave(target);
    return;
  }
  if (navigated && leaveGuard && leaveGuard.view !== id) leaveGuard = null;
  if (navigated) closeAllDialogs({restoreFocus: false});
  renderedRoute = signature;
  const [title, , , render] = views[id];
  const area = areaOf(id);
  // A record (one store, one saved audit) is a level below its screen.
  const detail = detailOf(id, params);
  const named = detail ? detail.label : title;
  if (topMenuOpen()) setTopMenu(false);
  // Focus goes to the new page's heading below, not back to the menu button.
  if (drawerOpen()) setDrawer(false, {restoreFocus: false});
  // The tab, the window list and history name the screen, not just the
  // product, and a record before the screen it belongs to.
  if (typeof document !== "undefined") document.title = `${detail ? `${detail.label} — ` : ""}${title} — VecShield`;
  if (navigated) rememberRecent(id, params);
  pageHeaderShown = false;
  document.querySelectorAll(".nav-btn").forEach(btn => {
    // A system link marks its own screen; an area button marks its area.
    const active = btn.classList.contains("nav-sys")
      ? btn.dataset.view === id
      : area && btn.dataset.area === area[0];
    active ? btn.setAttribute("aria-current", "page") : btn.removeAttribute("aria-current");
  });
  const chrome = document.getElementById("view-chrome");
  // A list's tab already says where you are; a record adds the trail above it.
  if (chrome) {
    // A record's trail already names its screen, so the screen's view
    // switch (Criteria · Frameworks) is left to the list.
    chrome.replaceChildren(...[detail ? breadcrumbs(id, params) : "", areaTabs(id, {detail: Boolean(detail)}),
                               detail ? "" : subviewSwitch(id)].filter(Boolean));
  }
  const content = document.getElementById("content");
  content.replaceChildren(loadingState(`Loading ${named}`));
  // A new page starts at its top. A redraw of the same page keeps its place.
  if (navigated) {
    const scroller = document.scrollingElement || document.documentElement;
    if (scroller) scroller.scrollTop = 0;
  }
  announce(`Loading ${named}`);
  // Each screen defines a glossary term at its own first use of it.
  definedTerms = new Set();
  try {
    const node = await render();
    if (state.authScreen) return;
    content.replaceChildren(node);
    ensurePageHeader(content, id);
    announce(`${named} ready`);
    await checkHealth();
  } catch (e) {
    if (state.authScreen) return;
    const restricted = e.status === 401 || e.status === 403;
    pageHeaderShown = false;
    content.replaceChildren(panel(restricted ? "Access restricted" : "Request failed",
      h("div", {},
        errorState(unavailableReason(e), () => route()),
        // The token field is in the header; saying so beats leaving someone to
        // find it. With sign-in on, a refusal is about the role, not a token.
        restricted
          ? statusLine(state.auth.login_enabled
              ? "Your role does not allow this. An admin can change your roles."
              : "Enter a bearer token in the header, then retry.", "info")
          : "")));
    ensurePageHeader(content, id);
    announce(`${named} failed to load`);
  }
  if (state.authScreen) return;
  // Focus follows the route so the next Tab continues from the new page, not
  // from wherever the old one left off.
  document.getElementById("page-title")?.focus?.();
}

// The theme follows the operating system unless someone chooses otherwise.
// theme.js applies it before the stylesheet paints; the console only keeps it
// current. A stored choice is an override, and toggling back to what the
// system prefers drops the override so the console follows the system again.
const THEME_KEY = "vecshield_theme";

function storedTheme() {
  try {
    const value = globalThis.localStorage?.getItem?.(THEME_KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch { return null; } // blocked storage or private mode
}

// What the system prefers, or null where that cannot be asked.
function systemTheme() {
  const query = globalThis.matchMedia?.("(prefers-color-scheme: dark)");
  return query ? (query.matches ? "dark" : "light") : null;
}

function effectiveTheme() {
  return document.documentElement.dataset.theme || systemTheme() || "light";
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  syncThemeIcon();
}

function toggleTheme() {
  const next = effectiveTheme() === "dark" ? "light" : "dark";
  try {
    if (next === systemTheme()) localStorage.removeItem(THEME_KEY);
    else localStorage.setItem(THEME_KEY, next);
  } catch { /* storage blocked: the choice lasts for this page only */ }
  applyTheme(next);
}

// Settings names the choice outright: System drops the override, Light and
// Dark keep one even when it matches the system today.
function themeChoice() {
  return storedTheme() || "system";
}

function setThemeChoice(choice) {
  const fixed = choice === "light" || choice === "dark";
  try {
    if (fixed) localStorage.setItem(THEME_KEY, choice);
    else localStorage.removeItem(THEME_KEY);
  } catch { /* storage blocked: the choice lasts for this page only */ }
  applyTheme(fixed ? choice : systemTheme() || "light");
}

function syncThemeIcon() {
  // The Settings control follows the header toggle when both are on screen.
  const choice = themeChoice();
  for (const seg of document.querySelectorAll?.(".theme-choice .seg") || []) {
    const on = seg.dataset?.choice === choice;
    seg.className = on ? "seg seg-on" : "seg";
    seg.setAttribute("aria-pressed", String(on));
  }
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  const dark = effectiveTheme() === "dark";
  btn.replaceChildren(icon(dark ? "sun" : "moon"));
  btn.title = dark ? "Switch to light theme" : "Switch to dark theme";
  btn.setAttribute("aria-label", btn.title);
}

// ---------------------------------------------------------------- account ---
// Sign-in, the password change a temporary password forces, and who is signed
// in. When the server has sign-in off, none of this shows: the console keeps
// the bearer token field it always had. Each account screen replaces the
// whole console (not a dialog over it), because nothing behind it is usable
// until it is done.

// Most privileged first: the role a person is introduced by.
const ROLE_ORDER = ["admin", "compliance", "operator", "viewer"];
const ROLE_HINT = {
  viewer: "reads everything",
  operator: "runs assessments and stages fixes",
  compliance: "decides criteria, evidence and approvals",
  admin: "every role, plus stores, policies and users",
};

function sortedRoles(roles) {
  const list = Array.isArray(roles) ? roles.map(String) : [];
  return [...new Set(list)].sort((a, b) =>
    (ROLE_ORDER.indexOf(a) + 1 || 99) - (ROLE_ORDER.indexOf(b) + 1 || 99) || a.localeCompare(b));
}

function primaryRole(user) {
  return sortedRoles(user?.roles?.length ? user.roles : user?.effective_roles)[0] || "";
}

function isAdmin() {
  const user = state.auth.user;
  return Boolean(user && [...(user.effective_roles || []), ...(user.roles || [])].includes("admin"));
}

// ------------------------------------------------------------ permissions ---
// What the principal /auth/session named may do. The server enforces every
// route; this only keeps the console from offering a control that ends in a
// refusal. Admin implies every role; compliance does not imply operator. With
// no known principal (a token deployment before a token is entered) nothing is
// withheld, and the server's answer is what the reader sees.
function can(role) {
  const user = state.auth.user;
  if (!user) return true;
  const held = new Set([...(user.effective_roles || []), ...(user.roles || [])].map(String));
  return held.has("admin") || held.has(role);
}

// Store administration needs both: a server that allows it, and an admin.
function storeAdmin() {
  return state.admin !== false && can("admin");
}

function roleNeed(role) {
  return `Needs the ${role} role.`;
}

// A control this reader may not use: kept in place, disabled, with the reason
// beside it, so the page reads the same for everyone and nothing leads to a
// 403. A reader who may use it gets the control unchanged.
function gated(role, control, reason = roleNeed(role)) {
  if (can(role)) return control;
  control.disabled = true;
  control.setAttribute("aria-disabled", "true");
  control.title = reason;
  return h("span", {class: "gated"}, control, h("span", {class: "gated-why"}, icon("lock"), reason));
}

// A refusal as the server gave it. "requires role: operator" reads as the
// role it needs; anything else (a second-person rule, a state conflict) is
// shown in the server's own words.
function refusalText(error) {
  const detail = String(error?.detail || error?.message || "").trim();
  const role = /^requires role: (.+)$/i.exec(detail);
  if (role) return roleNeed(role[1]);
  return sentence(detail) || "The server refused this.";
}

// The refusal, inline beside the control that met it, announced.
function refusalLine(error, prefix = "") {
  const text = error?.status === 403 ? refusalText(error) : error?.message || "The request failed.";
  return statusLine(prefix ? `${prefix}: ${text}` : text, "error", {live: true});
}

// The operations of a staged plan that cannot run, with the reason each
// carries. A plan staged from several fixes is only as runnable as its worst
// operation, and one with no operations has nothing to run.
function blockedOperations(plan) {
  const ops = plan?.operations || [];
  return ops.length ? ops.filter(o => !o.runnable) : [{support_reason: "it has no operations"}];
}

// A screen some readers must not be offered. The server still decides; this
// only keeps a link from leading to a refusal.
function viewAvailable(id) {
  if (id === "users") return state.auth.login_enabled && isAdmin();
  // Delivery sinks are read and written by an admin only.
  if (id === "alerting") return can("admin");
  return true;
}

// Server messages arrive lower-case ("invalid username or password").
function sentence(text) {
  const value = String(text || "").trim();
  if (!value) return "";
  const capital = value[0].toUpperCase() + value.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
}

function applySession(session) {
  const policy = session?.password_policy || {};
  state.auth = {
    login_enabled: Boolean(session?.login_enabled),
    authenticated: Boolean(session?.authenticated),
    user: session?.user || null,
    password_policy: {min_length: Number(policy.min_length) || 12},
  };
}

// An older server has no /auth/session; it is a token or open deployment, so
// the console carries on exactly as before.
async function loadSession() {
  try {
    applySession(await api("/auth/session"));
  } catch {
    applySession(null);
  }
}

async function startConsole() {
  await loadSession();
  const {login_enabled, authenticated, user} = state.auth;
  if (login_enabled && !authenticated) return showSignIn();
  if (user?.must_change_password) return showPasswordScreen({forced: true});
  return enterConsole();
}

function enterConsole() {
  state.authScreen = null;
  renderedRoute = null;
  pageHeaderShown = false;
  buildShell();
  return route();
}

// Forget the data this browser read with the last person's permissions.
function forgetCachedData() {
  state.stores = [];
  state.schemas = {};
  state.policies = [];
  state.templates = [];
  state.pack = null;
  state.admin = null;
  state.approvals = undefined;
  findingsCoverage = null;
  findingsCoverageReady = null;
  chunkCache.clear();
  try { sessionStorage.removeItem("vecshield_store"); } catch { /* private mode */ }
  try { sessionStorage.removeItem(RECENT_KEY); } catch { /* private mode */ }
}

// Forget what this browser holds for the last person: their token, who they
// are, and data read with their permissions.
function forgetSession() {
  state.token = "";
  try { sessionStorage.removeItem("vecshield_token"); } catch { /* private mode */ }
  state.auth = {...state.auth, authenticated: false, user: null};
  forgetCachedData();
}

function sessionExpired() {
  if (state.authScreen) return;
  forgetSession();
  showSignIn({notice: ["Your session ended. Sign in to continue.", "medium"]});
}

// Signed out only once the server says so. Without that answer the session
// may still be live on the server, so the console does not claim otherwise:
// it drops what it had read, says what happened, and offers to try again.
async function signOut() {
  try {
    await api("/auth/logout", {method: "POST"});
  } catch (e) {
    forgetCachedData();
    return showSignOutFailed(e);
  }
  forgetSession();
  showSignIn({notice: ["You signed out.", "ok"]});
}

function showSignOutFailed(error) {
  const retry = h("button", {class: "btn primary auth-submit", type: "button", onclick: () => {
    retry.disabled = true;
    retry.textContent = "Signing out…";
    signOut();
  }}, "Retry sign-out");
  authFrame("signout", "Sign-out did not complete",
    statusLine("Could not reach the server; your session may still be active.", "error", {live: true}),
    error?.status ? h("p", {class: "sub"}, `The server answered ${error.status}: ${sentence(error.message)}`) : "",
    h("div", {class: "auth-form"},
      retry,
      h("button", {class: "link auth-alt", type: "button", onclick: () => enterConsole()}, "Back to the console")));
  retry.focus?.();
  return {retry};
}

function authFrame(screen, title, ...body) {
  closeAllDialogs({restoreFocus: false});
  closeRowMenu();
  state.authScreen = screen;
  root.replaceChildren(
    h("div", {class: "auth-page"},
      h("div", {class: "auth-tools"},
        h("button", {class: "icon-btn", id: "theme-toggle", type: "button", title: "Toggle theme",
                     "aria-label": "Toggle theme", onclick: toggleTheme}, icon("moon"))),
      h("main", {class: "auth-card", "aria-labelledby": "auth-title"},
        h("div", {class: "auth-brand"},
          h("img", {class: "auth-logo", src: "/static/assets/vecshield-mark.svg", alt: "", width: "44", height: "44"}),
          h("div", {}, h("strong", {}, "VecShield"), h("span", {}, "Privacy & Compliance"))),
        h("h1", {id: "auth-title", tabindex: "-1"}, title),
        ...body)));
  syncThemeIcon();
}

// The inline error under an account form. It is a live alert, so a failed
// sign-in is announced without moving focus off the field being retyped.
function authError() {
  return h("p", {class: "auth-error", role: "alert"});
}

function setAuthError(node, message, input = null) {
  node.replaceChildren(message ? h("span", {class: "note-icon sev-error"}, icon("sev-critical")) : "",
                       message ? h("span", {}, message) : "");
  input?.setAttribute("aria-invalid", message ? "true" : "false");
}

function showSignIn({notice = null} = {}) {
  const username = textInput("", {name: "username", autocomplete: "username", autocapitalize: "none",
                                  spellcheck: "false", required: true});
  const password = textInput("", {type: "password", name: "password", autocomplete: "current-password",
                                  required: true});
  const error = authError();
  const submit = h("button", {class: "btn primary auth-submit", type: "submit"}, "Sign in");

  async function signIn(event) {
    event?.preventDefault?.();
    const name = username.value.trim();
    if (!name || !password.value) {
      setAuthError(error, "Enter your username and password.");
      (name ? password : username).focus?.();
      return;
    }
    submit.disabled = true;
    submit.textContent = "Signing in…";
    setAuthError(error, "");
    try {
      const result = await api("/auth/login", {method: "POST",
        body: JSON.stringify({username: name, password: password.value})});
      // A token from an earlier token session must not ride along with the
      // cookie this sign-in just set.
      state.token = "";
      try { sessionStorage.removeItem("vecshield_token"); } catch { /* private mode */ }
      state.auth = {...state.auth, authenticated: true, user: result?.user || {username: name}};
      if (state.auth.user.must_change_password) showPasswordScreen({forced: true});
      else await enterConsole();
    } catch (e) {
      submit.disabled = false;
      submit.textContent = "Sign in";
      password.value = "";
      setAuthError(error, sentence(e.message) || "Sign-in failed.", password);
      password.focus?.();
    }
  }

  authFrame("signin", "Sign in",
    notice ? statusLine(notice[0], notice[1]) : "",
    h("form", {class: "auth-form", onsubmit: signIn, novalidate: true},
      field("Username", username),
      field("Password", password),
      error,
      submit));
  username.focus?.();
  return {username, password, submit, error};
}

// The change-password form, shared by the screen a temporary password forces
// and by Settings. `onSaved` gets the server's answer once the change is made;
// `after` is appended below the submit button.
function passwordForm({submitLabel = "Change password", onSaved, after = "", className = ""} = {}) {
  const user = state.auth.user || {};
  const min = state.auth.password_policy?.min_length || 12;
  const current = textInput("", {type: "password", name: "current-password",
                                 autocomplete: "current-password", required: true});
  const next = textInput("", {type: "password", name: "new-password", autocomplete: "new-password",
                              required: true, minlength: String(min), "aria-describedby": "password-rule"});
  const confirm = textInput("", {type: "password", name: "confirm-password", autocomplete: "new-password",
                                 required: true});
  const error = authError();
  const submit = h("button", {class: "btn primary auth-submit", type: "submit"}, submitLabel);

  function problem() {
    if (!current.value) return [current, "Enter your current password."];
    if (next.value.length < min) return [next, `Use at least ${min} characters.`];
    if (next.value === current.value) return [next, "Choose a password different from the current one."];
    if (confirm.value !== next.value) return [confirm, "The new passwords do not match."];
    return null;
  }

  async function save(event) {
    event?.preventDefault?.();
    for (const input of [current, next, confirm]) input.setAttribute("aria-invalid", "false");
    const issue = problem();
    if (issue) {
      setAuthError(error, issue[1], issue[0]);
      issue[0].focus?.();
      return;
    }
    submit.disabled = true;
    setAuthError(error, "");
    try {
      const result = await api("/auth/password", {method: "POST",
        body: JSON.stringify({current_password: current.value, new_password: next.value})});
      state.auth = {...state.auth, authenticated: true,
                    user: result?.user || {...user, must_change_password: false}};
      for (const input of [current, next, confirm]) input.value = "";
      submit.disabled = false;
      await onSaved?.(result);
    } catch (e) {
      submit.disabled = false;
      const wrongCurrent = e.status === 401;
      setAuthError(error, sentence(e.message) || "The password was not changed.",
                   wrongCurrent ? current : next);
      (wrongCurrent ? current : next).focus?.();
    }
  }

  const form = h("form", {class: className ? `auth-form ${className}` : "auth-form", onsubmit: save,
                          novalidate: true},
    field("Current password", current),
    h("label", {class: "field"}, h("span", {}, "New password"), next,
      h("small", {class: "auth-hint", id: "password-rule"}, `At least ${min} characters.`)),
    field("Confirm new password", confirm),
    error,
    submit,
    after);
  return {form, current, next, confirm, submit, error};
}

function showPasswordScreen({forced = false} = {}) {
  if (forced && state.authScreen === "password") return null;
  const user = state.auth.user || {};
  const parts = passwordForm({
    submitLabel: forced ? "Save and continue" : "Change password",
    onSaved: async () => {
      await enterConsole();
      toast("Password changed.");
    },
    after: h("button", {class: "link auth-alt", type: "button",
                        onclick: () => (forced ? signOut() : enterConsole())},
      forced ? "Sign out" : "Cancel"),
  });
  authFrame("password", forced ? "Choose a new password" : "Change password",
    h("p", {class: "auth-lead"},
      forced ? "Your account has a temporary password. Choose your own to continue." : "",
      forced ? " " : "",
      user.username ? ["Signed in as ", h("strong", {}, user.username), "."] : ""),
    parts.form);
  parts.current.focus?.();
  const {current, next, confirm, submit, error} = parts;
  return {current, next, confirm, submit, error};
}

// The header's account control, in place of the token field.
function accountMenu() {
  const user = state.auth.user || {};
  const role = primaryRole(user);
  const toggle = h("button", {class: "account-btn", type: "button", id: "account-btn",
                              "aria-haspopup": "menu", "aria-expanded": "false"},
    icon("user"),
    h("span", {class: "sr-only"}, "Account: "),
    h("span", {class: "account-name"}, user.username || "Signed in"),
    role ? [h("span", {class: "sr-only"}, ", "), h("span", {class: "account-role"}, role)] : "");
  // The password change lives in Settings, beside the sessions it ends.
  return popupMenu(toggle, [
    {label: "Settings", glyph: "sliders", onclick: () => goTo("settings")},
    {label: "Sign out", glyph: "back", onclick: () => signOut()},
  ]);
}

// --------------------------------------------------------------- settings ---
// The reader's own page: who they are signed in as, their sessions and
// password, and this browser's preferences. Nothing here changes what anyone
// else sees or what the system does to data, and no preference loosens a
// control: masking, reveal, approvals and session limits are the server's.

// Only a local account has a password and sessions held here.
function ownsSession(user = state.auth.user) {
  return Boolean(state.auth.login_enabled && user && user.source === "session");
}

const SIGN_IN_METHOD = {
  session: "Local account",
  jwt: "Identity provider token (JWT)",
  static: "Static API token",
  open: "None: sign-in is off on this server",
};

// Why there is no password or session to manage, in the reader's terms.
function managedElsewhere(user) {
  if (!user) return "Enter a bearer token to see who the console is acting as.";
  if (user.source === "jwt") return "Your identity provider manages your password and sign-in; there is nothing to change here.";
  if (user.source === "static") return "This console is reached with an API token; there is no password or session to manage here.";
  if (user.source === "open") return "Sign-in is off on this server, so there is no account or session to manage.";
  return "Passwords and sessions are managed where your credential was issued.";
}

// "Firefox on Windows" from a stored user-agent string; the full string is
// kept in the title for anyone who needs it.
function browserLabel(agent) {
  const ua = String(agent || "");
  if (!ua) return "Unknown browser";
  const browser = /Edg\//.test(ua) ? "Edge"
    : /OPR\/|Opera/.test(ua) ? "Opera"
    : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome"
    : /Safari\//.test(ua) ? "Safari" : "";
  const os = /iPhone|iPad/.test(ua) ? "iOS"
    : /Android/.test(ua) ? "Android"
    : /Windows/.test(ua) ? "Windows"
    : /Mac OS X|Macintosh/.test(ua) ? "macOS"
    : /Linux/.test(ua) ? "Linux" : "";
  if (!browser && !os) return ua.length > 60 ? `${ua.slice(0, 57)}...` : ua;
  return os ? `${browser || "Browser"} on ${os}` : browser;
}

function browserTimeZone() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch { return ""; }
}

async function renderSettings() {
  const user = state.auth.user;
  const local = ownsSession(user);
  const box = h("div", {class: "settings-view"});
  box.append(pageHeader("settings"));

  // ---- profile
  const since = h("span", {}, local ? h("span", {class: "sub"}, "Reading...") : "");
  const roles = sortedRoles(user?.roles);
  const implied = sortedRoles(user?.effective_roles).filter(r => !roles.includes(r));
  box.append(panel("Profile", user
    ? h("dl", {class: "kv"},
        h("dt", {}, "Username"), h("dd", {}, h("span", {class: "strong mono"}, user.username || "-")),
        h("dt", {}, "Roles"), h("dd", {}, roleChips(roles),
          implied.length ? h("span", {class: "sub"}, ` Includes ${implied.join(", ")}.`) : ""),
        h("dt", {}, "Sign-in method"), h("dd", {}, SIGN_IN_METHOD[user.source] || user.source || "Unknown"),
        local ? [h("dt", {}, "Signed in since"), h("dd", {}, since)] : "")
    : unknownState("The console does not know who you are yet.", managedElsewhere(null))));

  // ---- security
  const security = h("div", {class: "settings-security"});
  box.append(panel("Security", security, null, {id: "settings-security"}));
  let password = null;
  const sessionsSlot = h("div", {});
  const notice = h("div", {class: "settings-notice"});
  const say = (message, tone = "ok") =>
    notice.replaceChildren(message ? statusLine(message, tone, {live: true}) : "");
  const revokeOthers = h("button", {class: "btn small", type: "button", disabled: true,
                                    onclick: () => endOtherSessions()},
    icon("close"), "Sign out other sessions");

  async function loadSessions() {
    sessionsSlot.replaceChildren(loadingState("Reading your sessions"));
    try {
      drawSessions(await api("/auth/sessions"));
    } catch (e) {
      since.replaceChildren("Unknown");
      sessionsSlot.replaceChildren(errorState(unavailableReason(e), loadSessions));
    }
  }

  function drawSessions(data) {
    const list = Array.isArray(data?.sessions) ? data.sessions : [];
    const current = data?.current || "";
    const mine = list.find(s => s.id === current);
    since.replaceChildren(mine ? formatWhen(mine.created_at) : "Unknown");
    const others = list.filter(s => s.id !== current);
    revokeOthers.disabled = !others.length;
    if (!list.length) {
      sessionsSlot.replaceChildren(emptyState("No live sessions are recorded."));
      return;
    }
    const rows = list.map(s => {
      const here = s.id === current;
      return h("tr", {class: here ? "session-current" : ""},
        h("td", {}, h("span", {title: s.user_agent || null}, browserLabel(s.user_agent)),
          here ? [" ", stateChip("ok", "this session")] : ""),
        h("td", {}, formatWhen(s.created_at)),
        h("td", {}, formatWhen(s.last_seen_at)),
        h("td", {}, formatWhen(s.expires_at)),
        h("td", {}, here
          ? h("button", {class: "btn small", type: "button", onclick: () => signOut()}, "Sign out")
          : h("button", {class: "btn small", type: "button",
                         "aria-label": `Sign out ${browserLabel(s.user_agent)} session`,
                         onclick: () => endSession(s)}, "Sign out")));
    });
    sessionsSlot.replaceChildren(
      h("p", {class: "sub settings-count"},
        `${plural(list.length, "live session")}. Sessions end after a period without activity, and at the time shown even when in use.`),
      table(["Browser", "Signed in", "Last active", "Expires", ""], rows));
  }

  async function endSession(s) {
    try {
      await api(`/auth/sessions/${encodeURIComponent(s.id)}`, {method: "DELETE"});
      say(`The ${browserLabel(s.user_agent)} session was signed out.`);
    } catch (e) {
      say(refusalText(e), "error");
    }
    await loadSessions();
  }

  async function endOtherSessions() {
    const ok = await confirmAction({
      title: "Sign out other sessions?",
      message: "Every other browser signed in as you is signed out and must sign in again. This session stays signed in.",
      confirmLabel: "Sign out others", danger: true});
    if (!ok) return;
    try {
      const result = await api("/auth/sessions/revoke-others", {method: "POST"});
      say(`${plural(result?.revoked || 0, "other session")} signed out.`);
    } catch (e) {
      say(refusalText(e), "error");
    }
    await loadSessions();
  }

  if (local) {
    password = passwordForm({
      className: "settings-password",
      onSaved: async () => {
        say("Password changed. Your other sessions were signed out.");
        await loadSessions();
      },
    });
    security.append(notice,
      h("h3", {class: "settings-sub"}, "Password"),
      password.form,
      h("div", {class: "settings-sub-head"},
        h("h3", {class: "settings-sub"}, "Sessions"), revokeOthers),
      sessionsSlot);
  } else {
    security.append(statusLine(managedElsewhere(user), "info"));
  }

  // ---- preferences
  const sample = h("span", {class: "sub"});
  const drawSample = () => sample.replaceChildren(`Now: ${localTime(Date.now())}`);
  drawSample();
  const zone = browserTimeZone();
  box.append(panel("Preferences", h("div", {class: "settings-prefs"},
    statusLine("Saved in this browser only. They stay when you sign out and apply to anyone using this browser.", "info"),
    h("div", {class: "pref-row"},
      h("span", {class: "pref-label", "aria-hidden": "true"}, "Theme"),
      segmented({label: "Theme", className: "theme-choice", dataKey: "choice", value: themeChoice(),
                 options: [["system", "System"], ["light", "Light"], ["dark", "Dark"]],
                 onPick: setThemeChoice})),
    h("div", {class: "pref-row"},
      h("span", {class: "pref-label", "aria-hidden": "true"}, "Times shown in"),
      segmented({label: "Times shown in", className: "time-choice", dataKey: "zone", value: timeZoneChoice,
                 options: [["local", zone ? `Local (${zone})` : "Local"], ["utc", "UTC"]],
                 onPick: choice => { setTimeZone(choice); drawSample(); }}),
      sample,
      h("small", {class: "auth-hint"},
        "Changes the console's display only. Exports, reports and evidence keep their own timestamps.")))));

  if (local) {
    await loadSessions();
    if (param("focus") === "password") setTimeout(() => password?.current.focus?.(), 0);
  }
  return box;
}

async function checkHealth() {
  try {
    const health = await api("/healthz");
    setHealth("ok", `Operational · ${number(health.stores)} store${health.stores === 1 ? "" : "s"}`);
  } catch {}
  try {
    const version = await api("/version");
    state.approvals = version.approvals || null;
    document.getElementById("version-foot").textContent = `VecShield ${version.version || "unknown"} · detectors ${version.detection_version || "unknown"}`;
  } catch {}
}

// Who may approve what they proposed, as this deployment has it. Read from
// /version; until that arrives the copy assumes the strict rule, which is the
// only assumption that cannot overstate what is allowed.
async function approvalsPolicy() {
  if (state.approvals === undefined || state.approvals === null) {
    try { state.approvals = (await api("/version")).approvals || null; } catch { state.approvals = null; }
  }
  return state.approvals || {separation_of_duties: "required", self_approval: "never"};
}

function approverSentence(what) {
  const mode = (state.approvals || {}).separation_of_duties || "required";
  if (mode === "off") {
    return `Separation of duties is off here: whoever holds the role may approve ${what}, including its author. Self-approvals are recorded as such.`;
  }
  if (mode === "admin_may_self_approve") {
    return `An admin may approve ${what} even if they proposed it; that approval is recorded as self-approved. Anyone else needs a second person.`;
  }
  return `A second person must authorize ${what}; the author cannot.`;
}

function selfApprovedChip() {
  return stateChip("medium", "self-approved", {title: "The approver is the person who proposed it."});
}

// The overview answers "what needs me", not "what exists". It leads with the
// inbox the server assembles (/admin/home): each item is a count, what it is,
// and a link to where it is dealt with. Open findings are distinct
// fingerprints from each store's latest audit, so re-running an audit does not
// inflate them; the per-run totals only appear in the trend, labelled as such.
const HOME_KINDS = {
  plans_awaiting_approval: "plans awaiting approval",
  evidence_reviews_awaiting_decision: "evidence reviews awaiting a decision",
  exceptions_expired: "expired exceptions",
  exceptions_expiring: "exceptions about to expire",
  exceptions_awaiting_approval: "exceptions awaiting approval",
  crypto_gate_blocks: "stores the crypto gate would block",
  stores_never_assessed: "stores never assessed",
  stores_partial_coverage: "stores whose latest audit was partial",
};

const OPEN_FINDINGS_CAVEAT = "Zero findings does not establish complete assessment coverage. " +
  "Review each run's coverage and check outcomes.";

// A request the overview could not complete, said as the request, what came
// back, what it most likely means, and a way to try again. A route the server
// does not have (a bare 404 "Not Found") is almost always a server started
// from an older checkout than the console, so it is named as that.
function overviewRequestFailure(path, error, consequence, retry) {
  const missing = routeMissing(error);
  const status = error?.status ? ` (${error.status})` : "";
  const headline = missing
    ? `This server does not serve ${path}.`
    : `GET ${path} failed${status}: ${unavailableReason(error)}`;
  const cause = missing
    ? staleServerDetail(`GET ${path}`)
    : error?.status === 401 || error?.status === 403
      ? "Sign in with a token whose role can read this, then retry."
      : error?.status >= 500
        ? "The server hit an error answering it; its log has the detail."
        : !error?.status ? "The API could not be reached. Check that the server is running." : "";
  return h("div", {class: "overview-failure", role: "alert"},
    unavailableState(headline, consequence),
    cause ? h("p", {class: "sub overview-failure-cause"}, icon("info"), cause) : "",
    retry ? h("button", {class: "btn small", type: "button", onclick: retry}, icon("refresh"), "Retry") : "");
}

// The overview's kinds, each with a glyph so the inbox scans by shape as well
// as by words.
const HOME_GLYPH = {
  plans_awaiting_approval: "check", evidence_reviews_awaiting_decision: "file",
  exceptions_expired: "clock", exceptions_expiring: "clock", exceptions_awaiting_approval: "user",
  crypto_gate_blocks: "shield", stores_never_assessed: "db", stores_partial_coverage: "layers",
};

async function renderOverview() {
  await loadCore();
  const box = h("div", {class: "overview-page"});
  // Retry redraws the whole screen: every count on it comes from one pass.
  const retry = async () => {
    const fresh = await renderOverview();
    if (box.replaceWith) box.replaceWith(fresh);
  };
  const [homeResult, runtimeResult, trendResult, estateResult] = await Promise.allSettled([
    api("/admin/home"), api("/runtime/alerts/stats"),
    api("/admin/history/trend?days=30"), api("/admin/estate"),
  ]);
  const home = homeResult.status === "fulfilled" ? homeResult.value : null;
  const homeError = homeResult.status === "rejected" ? homeResult.reason : null;
  const runtime = runtimeResult.status === "fulfilled" ? runtimeResult.value : null;
  const estate = estateResult.status === "fulfilled" ? (estateResult.value.stores || []) : null;
  const estateError = estateResult.status === "rejected"
    ? unavailableReason(estateResult.reason) : "";

  box.append(pageHeader("overview",
    "What needs you, what is open, and what was never measured.",
    can("operator")
      ? h("button", {class: "btn primary", type: "button", onclick: () => goTo("assess")},
          icon("shield"), "Run an assessment")
      : null));

  // Counts only, and a count that could not be read says so.
  const storesCount = home?.stores || {};
  const known = value => (typeof value === "number" ? number(value) : "Unknown");
  box.append(h("div", {class: "page-meta"}, factList([
    ["Stores", known(storesCount.total)],
    ["Assessed", known(storesCount.assessed)],
    ["Never assessed", known(storesCount.never_assessed)],
    ["Runtime alerts", runtime ? number(runtime.total || 0) : "Unknown"],
  ], {className: "page-facts", itemClass: "page-fact", valueClass: "page-fact-v"})));

  // Inbox and open counts share the first row on a wide screen; estate and
  // the trend stay full width underneath so neither is a secondary panel.
  box.append(h("div", {class: "overview-lead"},
    panel("Needs you", needsYouView(home, homeError, retry)),
    panel("Open findings", openFindingsView(home, homeError, retry))));

  // ---- estate posture ----
  // The stores that most need a look come first: never assessed, then those
  // whose latest audit did not cover its scope, then the longest unassessed.
  // The full list, with what each store supports, is the Stores screen.
  const posture = postureOrder(estate || []);
  const shownStores = posture.slice(0, ESTATE_POSTURE_ROWS);
  const rows = shownStores.map(store => h("tr", {},
    h("td", {},
      h("div", {class: "mono"}, store.store_id),
      store.kind ? h("div", {class: "sub"}, store.kind) : ""),
    h("td", {}, lastAssessedCell(store)),
    h("td", {}, coverageCell(store)),
    h("td", {class: "estate-posture-act"}, can("operator")
      ? h("button", {class: "btn small", type: "button",
                     onclick: () => goTo("assess", {store: store.store_id})},
          store.last_assessed ? "Re-assess" : "Assess")
      : "")));
  const allStores = !estateError && posture.length > shownStores.length
    ? h("button", {class: "link", type: "button", onclick: () => goTo("stores")},
        `All ${number(posture.length)} stores`, h("span", {"aria-hidden": "true"}, " →"))
    : null;
  box.append(panel("Estate posture",
    estateError
      ? overviewRequestFailure("/admin/estate", estateResult.reason, "The estate summary could not be read.", retry)
      : rows.length
        ? table(["Store", "Last assessed", "Coverage of that run", ""], rows,
                {tableClass: "estate-posture"})
        : emptyState("No stores are registered yet.",
            {action: () => goTo("stores"), actionLabel: "Connect a store"}),
    allStores));

  // ---- recorded findings over time, per run ----
  const trendOk = trendResult.status === "fulfilled" && trendResult.value.available !== false;
  box.append(panel("Findings recorded over time", trendOk
    ? h("div", {},
        // These are per-run totals; the note says so beside the chart.
        statusLine(trendResult.value.note ||
          "Findings recorded per run: re-running a scan counts its findings again. " +
          "These are not distinct open findings.", "info"),
        trendChart(trendResult.value.trend || [], {days: 30}))
    : trendResult.status === "rejected"
      ? overviewRequestFailure("/admin/history/trend", trendResult.reason,
          "Findings over time come from recorded scan history.", retry)
      : unavailableState("Trend history is unavailable.",
          "Findings over time come from recorded scan history.")));
  return box;
}

function homeItemDetail(item) {
  const parts = [];
  if (item.kind === "plans_awaiting_approval") {
    parts.push(`you may approve ${number(item.you_may_approve || 0)}`);
    if (item.needs_second_person) parts.push(`${number(item.needs_second_person)} need a second person`);
  }
  if (item.kind === "exceptions_expiring" && item.window_days) {
    parts.push(`within ${number(item.window_days)} days`);
  }
  if (item.by_status) {
    parts.push(Object.entries(item.by_status).map(([k, n]) => `${k.replace(/_/g, " ")} ${number(n)}`).join(" · "));
  }
  if ((item.stores || []).length) {
    const shown = item.stores.slice(0, 4).join(", ");
    parts.push(item.stores.length > 4 ? `${shown} +${number(item.stores.length - 4)} more` : shown);
  }
  return parts.join(" · ");
}

function needsYouView(home, homeError, retry) {
  if (homeError) {
    return overviewRequestFailure("/admin/home", homeError,
      "The inbox could not be read, so this is not a list of nothing to do.", retry);
  }
  if (!home || home.history_available === false) {
    return unavailableState(home?.note || "Scan history is not configured.",
      "Plans, exceptions, reviews and audits are read from scan history.");
  }
  // "Nothing needs you" is only said when the server says what it checked.
  if (!Array.isArray(home.needs_you) || !Array.isArray(home.checked)) {
    return unavailableState("The inbox came back incomplete.",
      "Without the list of what was checked, an empty inbox would be a guess.");
  }
  const items = home.needs_you;
  const present = new Set(items.map(i => i.kind));
  const checkedQuiet = (home.checked || []).filter(k => !present.has(k)).map(k => HOME_KINDS[k] || k.replace(/_/g, " "));
  const unavailable = (home.unavailable || []).map(u => statusLine(
    `Could not check ${String(u.check || "").replace(/_/g, " ")}` +
    `${u.store_id ? ` for ${u.store_id}` : ""}: ${u.reason || "unavailable"}. This is not a clear result.`, "medium"));
  const policies = state.policiesError
    ? statusLine(`Policies could not be read: ${state.policiesError} Every governance result depends on them.`, "medium")
    : "";
  if (!items.length) {
    return h("div", {class: "inbox-empty"},
      statusLine("Nothing needs you right now.", "ok"),
      checkedQuiet.length ? h("p", {class: "sub"}, `Checked: ${checkedQuiet.join(", ")}.`) : "",
      ...unavailable, policies);
  }
  return h("div", {},
    h("ul", {class: "inbox"}, items.map(item => {
      const target = item.target || {};
      const detail = homeItemDetail(item);
      return h("li", {class: "inbox-row", dataset: {kind: item.kind}},
        h("span", {class: "inbox-count"}, HOME_GLYPH[item.kind] ? icon(HOME_GLYPH[item.kind]) : "", number(item.count)),
        h("div", {class: "inbox-text"},
          h("div", {class: "strong"}, item.title),
          detail ? h("div", {class: "sub"}, detail) : ""),
        target.view && views[resolveView(target.view)]
          ? h("button", {class: "btn small", type: "button",
                         "aria-label": `${item.title}: open`,
                         onclick: () => goTo(target.view, target.params || {})},
              "Open", h("span", {"aria-hidden": "true"}, " →"))
          : "");
    })),
    checkedQuiet.length ? h("p", {class: "sub"}, `Also checked, nothing waiting: ${checkedQuiet.join(", ")}.`) : "",
    ...unavailable, policies);
}

function openFindingsView(home, homeError, retry) {
  if (homeError) {
    // The inbox panel above already explains the failure and offers the retry.
    return unavailableState(`Unknown: ${routeMissing(homeError) ? "this server does not serve /admin/home" : unavailableReason(homeError)}.`,
      "Open findings are counted from each store's latest audit, read in the same request as the inbox.");
  }
  const open = home?.open_findings;
  if (!open) {
    return unavailableState("Open findings are unavailable.",
      "They are counted from each store's latest saved audit, in scan history.");
  }
  const nothingAssessed = !open.stores_assessed;
  return h("div", {},
    severitySummary(open.by_severity, {
      variant: "list", label: sev => `${severityName(sev)} open`,
      link: sev => ["findings", {severity: sev}],
      empty: nothingAssessed ? "Nothing assessed yet" : "",
    }),
    h("p", {class: "sub"}, "Distinct findings from each store's latest audit." +
      (open.stores_never_assessed ? ` ${plural(open.stores_never_assessed, "store")} never assessed, which is not zero.` : "")),
    // This one changes what the numbers mean, so it stays in view.
    statusLine(OPEN_FINDINGS_CAVEAT, "info"),
    h("details", {class: "evidence-data about-numbers"},
      h("summary", {}, icon("info"), "About these numbers"),
      h("p", {class: "sub"},
        `Counted from the latest audit of ${plural(open.stores_assessed || 0, "store")}` +
        (open.stores_never_assessed ? `; ${plural(open.stores_never_assessed, "store")} never assessed, which is not zero` : "") +
        (open.suppressed ? `; ${number(open.suppressed)} suppressed, counted apart` : "") + "."),
      open.note ? h("p", {class: "sub"}, open.note) : ""));
}

function relativeDay(when) {
  const then = toMillis(when);
  if (!Number.isFinite(then)) return String(when || "unknown");
  // Whole days in either direction: 1.5 days ago is "yesterday", 1.5 days
  // ahead is "tomorrow". Expiries are in the future; an exception lapsing in
  // sixty days used to read "today", which is the opposite of what it needed to say.
  const diff = (Date.now() - then) / 86400000;
  const days = diff >= 0 ? Math.floor(diff) : -Math.floor(-diff);
  if (days < -1) return `in ${-days} days`;
  if (days === -1) return "tomorrow";
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  return `${days} days ago`;
}


// The Estate. Two questions, answered together: what do we have, and how much
// of it can we actually inspect? A connector's capabilities decide what any
// result from it can mean, so they belong beside the store, not buried in docs.

const CAPABILITY_MEANING = {
  query: "Isolation probes can run against it",
  delete: "Erasure can execute here",
  api_keys: "Access keys can be audited",
};

async function renderStores() {
  await loadCore();
  // `#/stores?store=<id>` is one store's page. It replaces the estate table
  // rather than appearing under it, where it landed below the fold and read
  // as a button that did nothing.
  const selected = param("store");
  if (selected) return storeDetailView(selected);
  const box = h("div", {class: "estate-view"});
  box.append(pageHeader("stores", "What is connected, and how much of it can be inspected.",
    storeAdmin()
      ? h("button", {class: "btn primary", type: "button", onclick: () => storeModal()},
          icon("plus"), "Add store")
      : ""));

  if (!state.stores.length) {
    box.append(firstRunPanel());
    return box;
  }

  // The Estate screen exists to say what each store supports, so it always
  // opens every connector to find out. The Overview reads the estate without
  // probing and says capabilities are unknown there.
  const out = h("div", {});
  box.append(panel("Estate", h("div", {},
    h("p", {class: "sub"}, "Each store is opened when this page loads, to read what it supports."),
    out)));

  out.replaceChildren(loadingState("Opening each store to read what it supports"));
  try {
    const summary = await api("/admin/estate?probe=true");
    out.replaceChildren(estateTable(summary));
  } catch (e) {
    out.replaceChildren(errorState(unavailableReason(e), () => route()));
  }
  return box;
}

// When a store was last assessed, or a chip saying it never was: never is
// not "no findings". Shared by the Overview's estate posture and Stores.
function lastAssessedCell(store) {
  return store.last_assessed ? relativeDay(store.last_assessed) : stateChip("unknown", "Never assessed");
}

// The coverage of the store's latest audit; a store never assessed has none.
function coverageCell(store) {
  return store.last_assessed
    ? coverageChip((store.coverage || {}).status)
    : h("span", {class: "sub"}, "no coverage recorded");
}

// The Overview shows the stores that most need a look, not the whole estate:
// never assessed first, then a latest audit that did not cover its scope,
// then the longest since an assessment. Ties keep the server's order.
const ESTATE_POSTURE_ROWS = 8;

function postureOrder(stores) {
  const rank = store => !store.last_assessed ? 0
    : (store.coverage || {}).status !== "complete" ? 1 : 2;
  const when = store => {
    const at = toMillis(store.last_assessed);
    return Number.isFinite(at) ? at : -Infinity;
  };
  return stores.map((store, index) => ({store, index}))
    .sort((a, b) => rank(a.store) - rank(b.store) || when(a.store) - when(b.store) || a.index - b.index)
    .map(item => item.store);
}

function estateTable(summary) {
  const rows = (summary.stores || []).map(store => {
    const probe = store.probe || {};
    const severities = store.findings || {};
    const worst = severityOrder.find(sev => severities[sev]);
    return h("tr", {},
      h("td", {},
        h("div", {class: "strong mono store-id"}, store.store_id),
        h("div", {class: "sub nowrap"}, store.tenant_field
          ? ["Tenant field: ", h("span", {class: "mono"}, store.tenant_field)] : "No tenant field"),
        h("div", {class: "tag-row"}, h("span", {class: "tag"}, store.kind))),
      h("td", {}, storeHealth(probe)),
      h("td", {}, capabilityCell(probe)),
      h("td", {}, store.last_assessed
        ? h("div", {},
            h("div", {}, lastAssessedCell(store)),
            h("div", {class: "sub"}, coverageCell(store)))
        : lastAssessedCell(store)),
      h("td", {}, store.history_available === false
        ? h("span", {class: "sub"}, "history unavailable")
        : worst
          ? h("div", {}, badge(worst), h("div", {class: "sub"},
              `${number(store.findings_total)} recorded`))
          : h("span", {class: "sub"}, store.last_assessed ? "none recorded" : "not assessed")),
      h("td", {}, rowActions(
        h("button", {class: "btn small", type: "button", "aria-label": `Open ${store.store_id}`,
                     onclick: () => goTo("stores", {store: store.store_id})}, icon("eye"), "Open"),
        [
          can("operator") ? {label: "Assess", glyph: "shield", onclick: () => goTo("assess", {store: store.store_id})} : null,
          {label: "Test connection", glyph: "refresh", onclick: () => testStore(store.store_id)},
          storeAdmin() ? {label: "Edit connection", glyph: "edit", onclick: () => editStore(store.store_id)} : null,
          storeAdmin() ? {label: "Delete store", glyph: "trash", danger: true,
                                   onclick: () => deleteStore(store.store_id)} : null,
        ])));
  });
  return h("div", {},
    table(["Store", "Reachable", "Can inspect", "Last assessed", "Worst recorded", ""], rows),
    statusLine(summary.note || "", "info"));
}

function storeHealth(probe) {
  if (!probe.probed) return h("span", {class: "sub"}, "not probed");
  if (probe.reachable) {
    return h("div", {}, stateChip("ok", "reachable"),
      probe.collections != null
        ? h("div", {class: "sub nowrap"}, `${plural(probe.collections, "collection")} · ${plural(probe.chunks, "chunk")}`)
        : "");
  }
  return h("div", {}, stateChip("critical", "unreachable"),
    h("div", {class: "sub"}, probe.error || ""));
}

// What a connector cannot do bounds what its results can mean, so this cell
// distinguishes "cannot" from "we have not looked".
function capabilityCell(probe) {
  if (!probe.probed) return stateChip("unknown", "unknown");
  if (!probe.reachable) return stateChip("unknown", "unknown — unreachable");
  const caps = probe.capabilities || [];
  // The readability chip leads; the declared capabilities follow as one
  // wrapping row of tags, spaced and centred on the chip rather than butted
  // against it at a different height.
  return h("div", {},
    h("div", {class: "cap-row"},
      probe.content_enumerable
        ? stateChip("ok", "content readable")
        : stateChip("medium", "inventory only"),
      ...caps.map(c => h("span", {class: "tag", title: CAPABILITY_MEANING[c] || ""}, c))),
    probe.content_enumerable ? "" : h("div", {class: "sub"},
      "Chunk contents cannot be enumerated: classification, erasure, and DSAR " +
      "cannot see inside this store."));
}

// One store: what it is, whether it answered, what it holds, and where to go
// next. Its name is the page heading, so focus lands on it and it is the
// first thing on screen.
async function storeDetailView(storeId) {
  const box = h("div", {class: "estate-view store-detail"});
  const back = {label: "All stores", className: "store-back", onclick: () => climbOut("stores")};
  const store = (state.stores || []).find(s => s.store_id === storeId);
  if (!store) {
    box.append(pageHeader(storeId, "No store with this id is registered.", null, {literal: true, back}),
      panel("", emptyState("It may have been deleted or renamed.",
                           {action: () => goTo("stores"), actionLabel: "All stores"})));
    return box;
  }
  const [schemaResult, estateResult, changesResult, inventoryResult] = await Promise.allSettled([
    loadStoreSchema(storeId, 0, false),
    // The unprobed summary: history only. The schema read above is what opens
    // this store; probing the whole estate for one store would open them all.
    api("/admin/estate"),
    // Saved history only: neither of these opens the store.
    api(`/stores/${encodeURIComponent(storeId)}/changes`),
    api(`/stores/${encodeURIComponent(storeId)}/inventory/changes`),
  ]);
  const summary = estateResult.status === "fulfilled"
    ? (estateResult.value.stores || []).find(s => s.store_id === storeId) || {}
    : {};
  const severities = summary.findings || {};
  const worst = severityOrder.find(sev => severities[sev]);
  const schema = schemaResult.status === "fulfilled" ? schemaResult.value : null;
  const collections = schema?.collections || [];
  const chunks = collections.reduce((sum, c) => (c.count == null || sum == null ? null : sum + Number(c.count)), 0);

  box.append(pageHeader(storeId,
    [store.kind, store.description].filter(Boolean).join(" · ") || "Registered store",
    can("operator")
      ? h("button", {class: "btn primary", type: "button", onclick: () => goTo("assess", {store: storeId})},
          icon("shield"), "Assess")
      : null, {literal: true, back}));

  box.append(h("dl", {class: "kv-compact store-facts"},
    h("dt", {}, "Reachable"),
    h("dd", {}, schema ? stateChip("ok", "reachable") : stateChip("critical", "unreachable")),
    h("dt", {}, "Tenant field"),
    h("dd", {}, store.tenant_field ? h("span", {class: "mono"}, store.tenant_field) : h("span", {class: "sub"}, "none")),
    h("dt", {}, "Last assessed"),
    h("dd", {}, summary.last_assessed
      ? [relativeDay(summary.last_assessed), " ", coverageChip((summary.coverage || {}).status)]
      : estateResult.status === "fulfilled" ? stateChip("unknown", "Never assessed")
      : h("span", {class: "sub"}, "history unavailable")),
    h("dt", {}, "Worst recorded"),
    h("dd", {}, summary.history_available === false || estateResult.status !== "fulfilled"
      ? h("span", {class: "sub"}, "history unavailable")
      : worst ? [badge(worst), h("span", {class: "sub"}, ` ${number(summary.findings_total)} recorded`)]
      : h("span", {class: "sub"}, summary.last_assessed ? "none recorded" : "not assessed"))));

  box.append(h("div", {class: "bar store-links"},
    h("button", {class: "btn small", type: "button", onclick: () => goTo("schema", {store: storeId})},
      icon("list"), "Full schema"),
    h("button", {class: "btn small", type: "button", onclick: () => goTo("findings", {store: storeId})},
      icon("alert"), "Findings for this store"),
    h("button", {class: "btn small", type: "button", onclick: () => goTo("crypto", {store: storeId})},
      icon("lock"), "Crypto posture"),
    h("button", {class: "btn small", type: "button", onclick: () => testStore(storeId)},
      icon("refresh"), "Test connection"),
    storeAdmin()
      ? h("button", {class: "btn small", type: "button", onclick: () => editStore(storeId)},
          icon("edit"), "Edit connection")
      : ""));

  box.append(storeChangesPanel(storeId, changesResult, inventoryResult));

  box.append(panel(schema ? `Collections (${number(collections.length)})` : "Collections",
    !schema
      ? errorState(unavailableReason(schemaResult.reason), () => route())
      : collections.length
        ? h("div", {},
            table(["Collection", "Chunks", "Metadata fields"], collections.map(c => h("tr", {},
              // A collection opens its own page: findings, a live sample, fields.
              h("td", {class: "mono"}, h("button", {class: "link mono", type: "button",
                onclick: () => goTo("schema", {store: storeId, collection: c.name})}, c.name)),
              h("td", {}, c.count == null ? stateChip("unknown", "unknown") : number(c.count)),
              // This view lists collections without sampling their contents, so
              // the field count is unknown here, not zero. Rendering 0 would say
              // "this collection has no metadata", which nobody established.
              h("td", {}, metadataFieldCount(c))))),
            chunks == null ? "" : h("p", {class: "sub"}, `${number(chunks)} chunks in total.`))
        : emptyState("This store reports no collections.")));
  return box;
}

const CHANGE_LIST_ROWS = 5;
const EVENT_SEVERITY_RANK = {critical: 4, high: 3, medium: 2, low: 1, info: 0};

// What changed between this store's two latest saved audits. Fewer than two
// audits is "nothing to compare yet", never "no changes"; a finding that
// vanished from a check that did not run again is "not re-tested", never fixed.
function storeChangesPanel(storeId, changesResult, inventoryResult) {
  const title = "Since the last audit";
  if (changesResult.status === "rejected") {
    return panel(title, errorState(unavailableReason(changesResult.reason), () => route()));
  }
  const c = changesResult.value || {};
  if (c.compared !== true) {
    return panel(title, emptyState(
      sentence(c.reason || "There is no earlier saved audit to compare with"),
      can("operator") ? {action: () => goTo("assess", {store: storeId}), actionLabel: "Assess"} : {}));
  }
  const auditLink = (id, label) => id
    ? h("button", {class: "link", type: "button", onclick: () => goTo("history", {audit: id, store: storeId})}, label)
    : label;
  const total = key => Number(c[`${key}_total`] ?? (c[key] || []).length);
  const moved = total("new") + total("resolved") + total("not_retested");
  return panel(title, h("div", {class: "store-changes"},
    h("p", {class: "sub"},
      auditLink(c.before_audit_id, "Previous audit"), " (", formatWhen(c.before_at), ") compared with ",
      auditLink(c.after_audit_id, "latest audit"), " (", formatWhen(c.after_at), ")."),
    h("div", {class: "cap-row"},
      stateChip(total("new") ? "medium" : "info", `${number(total("new"))} new`),
      stateChip(total("resolved") ? "ok" : "info", `${number(total("resolved"))} resolved`),
      stateChip("unknown", `${number(total("not_retested"))} not re-tested, not resolved`,
                {title: "Gone from the latest audit, but the check that found it did not run to completion."}),
      stateChip("info", `${number(c.persistent || 0)} still present`)),
    moved ? "" : statusLine("No finding appeared or disappeared between these two audits.", "info"),
    changeList("New", c.new, total("new"), storeId),
    changeList("Resolved", c.resolved, total("resolved"), storeId),
    changeList("Not re-tested", c.not_retested, total("not_retested"), storeId),
    inventoryChanges(inventoryResult)));
}

function changeList(heading, entries, count, storeId) {
  const rows = (entries || []).slice(0, CHANGE_LIST_ROWS);
  if (!rows.length) return "";
  const more = count - rows.length;
  return h("div", {class: "change-group"},
    h("h3", {class: "change-h"}, `${heading} (${number(count)})`),
    h("ul", {class: "change-list"}, rows.map(e => h("li", {},
      badge(e.severity),
      e.id
        ? h("button", {class: "link", type: "button",
                       onclick: () => goTo("findings", {finding: e.id, store: storeId, scope: "all"})}, e.title || "Untitled finding")
        : h("span", {}, e.title || "Untitled finding"),
      e.collection ? h("span", {class: "sub mono"}, e.collection) : ""))),
    more > 0
      ? h("button", {class: "link", type: "button", onclick: () => goTo("findings", {store: storeId})},
          `and ${number(more)} more in Findings`)
      : "");
}

// Inventory changes compare the latest two audits that carried an inventory,
// which can be older than the pair above when a recent audit could not describe the store.
function inventoryChanges(result) {
  const heading = h("h3", {class: "change-h"}, "Inventory");
  if (result.status === "rejected") {
    return h("div", {class: "change-group"}, heading, result.reason?.status === 404
      ? h("p", {class: "sub"}, "No saved audit of this store carries an inventory yet.")
      : statusLine(unavailableReason(result.reason), "error"));
  }
  const inv = result.value || {};
  const events = (inv.events || []).slice().sort((a, b) =>
    (EVENT_SEVERITY_RANK[b.severity] ?? 0) - (EVENT_SEVERITY_RANK[a.severity] ?? 0));
  return h("div", {class: "change-group"}, heading,
    events.length
      ? h("ul", {class: "change-list"}, events.map(e => h("li", {}, badge(e.severity), h("span", {}, e.summary))))
      : h("p", {class: "sub"}, "No collection, size, model, alias, server or location change between the inventories compared."),
    inv.note ? h("p", {class: "sub"}, inv.note) : "");
}

// Metadata fields are only known when the collection was sampled. The API says
// so with `metadata_complete`; ignoring it turns "we did not look" into "there
// is nothing there".
function metadataFieldCount(collection) {
  const fields = collection.metadata_fields || collection.fields;
  const sampled = collection.metadata_complete === true ||
    Number(collection.sample_size || 0) > 0;
  if (!sampled) {
    return stateChip("unknown", "not sampled", {title: "No chunks were sampled for this view."});
  }
  const count = Array.isArray(fields) ? fields.length : Object.keys(fields || {}).length;
  return number(count);
}

// A console with nothing connected should say what to do, not show an empty table.
function firstRunPanel() {
  return panel("Start here", h("div", {class: "firstrun"},
    h("p", {}, "Nothing is connected yet. Three steps gets you a first assessment:"),
    h("ol", {class: "firstrun-steps"},
      h("li", {},
        h("strong", {}, "Connect a store."),
        " Credentials stay on the server; the console only ever refers to a store by its id.",
        h("div", {class: "bar"},
          storeAdmin()
            ? h("button", {class: "btn primary", type: "button", onclick: () => storeModal()},
                icon("plus"), "Add store")
            : h("span", {class: "sub"}, state.admin === false
                ? "Store administration is disabled on this server."
                : "An admin connects stores."))),
      h("li", {},
        h("strong", {}, "Run a baseline assessment."),
        " It classifies content, checks integrity and posture, and records what it " +
        "could not reach.",
        h("div", {class: "bar"},
          can("operator")
            ? h("button", {class: "btn", type: "button", onclick: () => goTo("assess")},
                icon("shield"), "Go to assessments")
            : h("span", {class: "sub"}, "An operator runs assessments."))),
      h("li", {},
        h("strong", {}, "Read the result, including its coverage."),
        " An assessment that inspected part of your data says so; zero findings over " +
        "partial coverage is not a clean result."))));
}


// One form for adding and editing a store. Editing keeps the store id (its
// scoped policies hang off it). A secret the API masked comes back as "***"
// and is shown as "stored value kept"; leaving it empty sends "***" back, which
// the server resolves to the stored secret, so an edit never clobbers one.
function storeModal(existing = null) {
  const editing = Boolean(existing);
  const id = textInput(existing?.store_id || "", {placeholder: "prod", disabled: editing});
  const kind = selectInput(Object.keys(connectorFields).map(k => [k, k]), existing?.kind || "chroma");
  const tenant = textInput(existing?.tenant_field || "", {placeholder: "tenant_id"});
  const desc = textInput(existing?.description || "", {placeholder: "Production knowledge base"});
  const fields = h("div", {class: "grid"});
  const known = () => new Set((connectorFields[kind.value] || []).map(([key]) => key));
  const drawFields = () => {
    const conn = existing && kind.value === existing.kind ? (existing.conn || {}) : {};
    fields.replaceChildren(...(connectorFields[kind.value] || []).map(([key, label, type]) => {
      const masked = conn[key] === "***";
      const input = textInput(masked ? "" : (conn[key] ?? ""), {
        type: type || "text", dataset: {key, masked: masked ? "1" : ""},
        placeholder: masked ? "Stored value kept; type to replace" : "",
      });
      return field(masked ? `${label} (stored)` : label, input);
    }));
  };
  kind.addEventListener("change", drawFields);
  drawFields();
  const result = h("div", {class: "store-test", "aria-live": "polite"});
  // The last test of the form as it stands. Any edit makes it stale.
  let lastTest = null;
  const invalidate = () => { lastTest = null; };
  kind.addEventListener("change", invalidate);
  fields.addEventListener("input", invalidate);

  function payloadConn() {
    const conn = {};
    // Keys this form does not show are kept as they are, masked or not.
    if (existing && kind.value === existing.kind) {
      for (const [key, value] of Object.entries(existing.conn || {})) {
        if (!known().has(key)) conn[key] = value;
      }
    }
    fields.querySelectorAll("input").forEach(input => {
      const value = input.value.trim();
      if (!value) {
        if (input.dataset.masked) conn[input.dataset.key] = "***";
        return;
      }
      conn[input.dataset.key] = input.type === "number" ? Number(value) : value;
    });
    return conn;
  }

  // Tries the form's current values without saving them. A masked secret goes
  // as "***" with the store id, and the server uses the stored one.
  async function testNow() {
    result.replaceChildren(loadingState("Trying these settings; nothing is saved"));
    const request = {kind: kind.value, conn: payloadConn()};
    if (editing) request.store_id = existing.store_id;
    let outcome;
    try {
      outcome = await api("/admin/stores/test-connection", {method: "POST", body: JSON.stringify(request)});
    } catch (e) {
      outcome = {ok: false, category: "refused", reason: unavailableReason(e)};
    }
    lastTest = outcome;
    result.replaceChildren(connectionTestResult(outcome));
    return outcome;
  }

  const body = h("div", {},
    h("div", {class: "grid"}, field("Store ID", id), field("Kind", kind), field("Tenant field", tenant), field("Description", desc)),
    fields,
    h("p", {class: "sub"}, "Use *_env fields for secrets. Values are resolved on the server and are not sent back to the browser."),
    h("div", {class: "store-test-bar"},
      h("button", {class: "btn small", type: "button", onclick: () => testNow()}, icon("refresh"), "Test connection"),
      h("span", {class: "sub"}, "Tries these settings before anything is saved. Each try is recorded in the audit log.")),
    result);

  modal(editing ? `Edit ${existing.store_id}` : "Add store", body, async () => {
    // Saving is never blocked on a test, but saving over a failed one is a
    // choice the reader makes knowingly.
    if (lastTest && lastTest.ok === false) {
      const go = await confirmAction({
        title: "Save anyway?",
        message: "The last connection test with these settings failed" +
                 (lastTest.category ? ` (${String(lastTest.category).replace(/_/g, " ")})` : "") +
                 ". Saving keeps them, and assessments of this store will fail until they work.",
        confirmLabel: "Save anyway",
      });
      if (!go) return;
    }
    const payload = {kind: kind.value, conn: payloadConn(),
                     tenant_field: tenant.value.trim() || null, description: desc.value.trim()};
    if (editing) {
      await api(`/admin/stores/${encodeURIComponent(existing.store_id)}`, {method: "PUT", body: JSON.stringify(payload)});
      state.schemas = {};
      toast("Store updated.");
    } else {
      await api("/admin/stores", {method: "POST", body: JSON.stringify({store_id: id.value.trim(), ...payload})});
      toast("Store added.");
    }
    closeModal();
    route();
  }, "Save");
}

// A pre-save test's outcome: what it reached, or why it could not. The server
// sends a category and a reason, never the connector's own error text, which
// can carry a credential.
function connectionTestResult(outcome) {
  if (outcome && outcome.ok) {
    const cols = outcome.collections || [];
    return h("div", {class: "test-ok"},
      statusLine(`These settings connect to ${outcome.endpoint ? storeLabel(outcome.endpoint) : "the store"}: ${plural(cols.length, "collection")} found. Nothing was saved.`, "ok", {live: true}),
      cols.length ? table(["Collection", "Count", "Dimension"], cols.map(c => h("tr", {},
        h("td", {class: "mono"}, c.name), h("td", {}, c.count == null ? stateChip("unknown", "unknown") : number(c.count)),
        h("td", {}, c.dimension || "-")))) : "");
  }
  return h("div", {class: "test-failed"},
    statusLine(`These settings did not connect${outcome?.category ? ` (${String(outcome.category).replace(/_/g, " ")})` : ""}: ` +
               `${outcome?.reason || "no reason was given"}` +
               `${outcome?.error_type ? ` [${outcome.error_type}]` : ""}`, "error", {live: true}));
}

async function editStore(storeId) {
  let existing;
  try { existing = await api(`/admin/stores/${encodeURIComponent(storeId)}`); }
  catch (e) { toast(unavailableReason(e), "err"); return; }
  storeModal(existing);
}

async function connectionTestView(storeId) {
  try {
    const r = await api(`/admin/stores/${encodeURIComponent(storeId)}/test`, {method: "POST"});
    const node = h("div", {},
      statusLine(`Connected to ${r.endpoint || storeId}: ${plural((r.collections || []).length, "collection")}.`, "ok", {live: true}),
      table(["Collection", "Count", "Dimension"], (r.collections || []).map(c => h("tr", {},
        h("td", {class: "mono"}, c.name), h("td", {}, number(c.count)), h("td", {}, c.dimension || "-")))));
    node.dataset.ok = "1";
    return node;
  } catch (e) {
    const node = h("div", {}, statusLine(`The connection test failed: ${unavailableReason(e)}`, "error", {live: true}));
    node.dataset.ok = "";
    return node;
  }
}

async function testStore(id) {
  const body = h("div", {}, loadingState("Testing the connection"));
  modal(`Connection test — ${id}`, body, null, "Close");
  body.replaceChildren(await connectionTestView(id));
}

// Deleting a store cannot be undone and takes its scoped policies with it, so
// the confirmation names them and asks for the store id to be typed.
async function deleteStore(id) {
  const scoped = (state.policies || []).filter(p => p.scope_store === id);
  const ok = await confirmAction({
    title: `Delete store ${id}?`,
    message: "This removes the store's registration. It cannot be undone from the console. " +
             "Reviewer decisions and applicability answers recorded for it stop applying; " +
             "they are kept as history, not deleted. " +
             (scoped.length
               ? `${plural(scoped.length, "policy", "policies")} scoped to this store will be removed with it.`
               : "No policy is scoped to this store."),
    details: scoped.length
      ? h("ul", {class: "confirm-list"}, scoped.map(p => h("li", {}, p.name || p.id)))
      : null,
    confirmLabel: "Delete store", danger: true,
    typed: id, typedLabel: "To confirm, type the store id ",
  });
  if (!ok) return;
  try {
    const result = await api(`/admin/stores/${encodeURIComponent(id)}`, {method: "DELETE"});
    const retired = result?.retired;
    toast(retired
      ? `Store deleted. ${plural(retired.reviewer_decisions || 0, "reviewer decision")} and ` +
        `${plural(retired.applicability_answers || 0, "applicability answer")} were retired and kept as history.`
      : "Store deleted. No scan history is configured, so nothing else was retired.");
    route();
  } catch (e) { toast(e.message, "err"); }
}

async function renderSchemaExplorer() {
  await loadCore();
  const box = h("div", {class: "estate-view"});
  const scope = scopedStore();
  const firstStore = scope.id;
  const store = selectInput([["", "Choose a store"], ...state.stores.map(s => [s.store_id, s.store_id])], firstStore);
  const sample = textInput(param("sample", "200"), {type: "number", min: "0", max: "5000"});
  const out = h("div", {});
  // A collection is a record of its store: its page is named for it, with
  // one way back to the store's collections.
  const focusName = store.value ? param("collection") : "";

  async function draw(force = false) {
    if (!store.value) {
      out.replaceChildren(panel("Schema", state.stores.length
        ? emptyState("Choose a store above to discover its collections and metadata.")
        : emptyState("No stores are registered. Add one first.",
                     {action: () => goTo("stores"), actionLabel: "Go to Stores"})));
      return;
    }
    out.replaceChildren(loadingState("Discovering schema"));
    try {
      const sampleSize = Math.max(0, Math.min(5000, Number(sample.value) || 0));
      const schema = await loadStoreSchema(store.value, sampleSize, force);
      const collection = focusName && (schema.collections || []).find(c => c.name === focusName);
      if (focusName && !collection) {
        out.replaceChildren(panel("Collection", unavailableState(
          `${store.value} reports no collection named ${focusName}.`,
          "It may have been renamed or removed since this link was made."),
          h("button", {class: "btn small", type: "button", onclick: leaveCollection},
            icon("back"), "All collections")));
        return;
      }
      out.replaceChildren(collection
        ? await collectionView(store.value, collection, schema)
        : schemaExplorerView(schema, store.value));
    } catch (e) {
      out.replaceChildren(panel("Schema discovery failed", errorState(e.message, () => draw(true))));
    }
  }

  store.addEventListener("change", () => {
    const leaving = Boolean(param("collection"));
    setParams({store: store.value, collection: ""});
    // Leaving a collection leaves its breadcrumb too, so the page is redrawn.
    if (leaving) route(); else draw(true);
  });
  sample.addEventListener("change", () => { setParams({sample: sample.value}); draw(true); });
  function leaveCollection() { setParams({collection: ""}); route(); }
  // The store is the screen's scope; refreshing re-reads it and is not the
  // screen's primary action, so it is a plain button.
  const refresh = h("button", {class: "btn", type: "button", onclick: () => draw(true)}, icon("refresh"), "Refresh");
  if (focusName) {
    box.append(pageHeader(h("span", {class: "mono"}, focusName),
      `A collection in ${store.value}: its findings, a live masked sample, and its metadata fields.`, refresh,
      {literal: true, scope: field("Store", store),
       back: {label: `All collections in ${store.value}`, className: "collection-back", onclick: leaveCollection}}));
  } else {
    box.append(pageHeader("schema", "Collections, vector counts, metadata fields, and sampled value counts.", refresh,
      {scope: [field("Store", store), field("Metadata sample", sample)]}));
  }
  box.append(rememberedStoreNote(scope));
  box.append(out);
  await draw();
  return box;
}

// The end of a long endpoint is the part that tells stores apart
// (".../stores/clinical-rag"), so that is the part kept on screen.
function endpointTail(text) {
  const uri = String(text).match(/^[a-z][a-z0-9+.-]*:\/\/(.*)$/i);
  const parts = (uri ? uri[1] : String(text)).split(/[/?#]/).filter(Boolean);
  return parts.length > 2 ? `…/${parts.slice(-2).join("/")}` : String(text);
}

function schemaExplorerView(schema, storeId = "") {
  const collections = schema.collections || [];
  const fields = schema.metadata_fields || [];
  const errors = schema.errors || [];
  // A missing list is "not reported", never "none": only a list the connector
  // returned empty says it declared nothing.
  const reported = Array.isArray(schema.capabilities);
  const capabilities = reported ? schema.capabilities : [];
  const endpoint = schema.name || schema.endpoint || "";
  return h("div", {},
    kpiGrid("schema-kpis",
      metric("Collections", number(schema.collection_count), schema.kind || "store"),
      // The endpoint can be a long file path or URL: one truncated line, the
      // whole of it on hover, instead of five wrapped lines under the count.
      metric("Vectors", number(schema.total_vectors),
             endpoint ? h("span", {class: "metric-path mono", title: endpoint}, endpointTail(endpoint)) : ""),
      metric("Metadata fields", number(fields.length), schema.content_enumerable ? `sample ${number(schema.sample_chunks)}` : "inventory only")),
    // Capability names are identifiers, not a headline: the same tags the
    // Stores screen uses, in one line under the counts rather than a tile
    // that would stretch the whole row to its height.
    h("div", {class: "schema-caps"},
      h("span", {class: "schema-caps-k"}, "Capabilities"), " ",
      capabilities.length
        ? h("span", {class: "cap-row"}, capabilities.map(c =>
            h("span", {class: "tag", title: CAPABILITY_MEANING[c] || ""}, c)))
        : h("span", {class: "sub"}, reported ? "none declared by the connector" : "not reported")),
    errors.length ? panel("Collection read errors", table(["Collection", "Detail"], errors.map(e => h("tr", {}, h("td", {class: "mono"}, e.collection), h("td", {}, e.detail))))) : "",
    panel("Collections", table(["Collection", "Vectors", "Dimension", "Metadata keys", "Sampled", ""], collections.map(c => h("tr", {},
      h("td", {}, h("button", {class: "link mono", type: "button",
                               onclick: () => { setParams({collection: c.name}); route(); }}, c.name)),
      h("td", {}, number(c.count)),
      h("td", {}, c.dimension || "-"),
      h("td", {}, number(c.metadata_key_count)),
      h("td", {}, c.sample_size ? `${number(c.sample_size)}${c.metadata_complete ? "" : "+"}` : "-"),
      h("td", {}, h("button", {class: "btn small", type: "button",
                               onclick: () => { setParams({collection: c.name}); route(); }},
        icon("eye"), "Open")))))),
    panel("Metadata fields", metadataFieldsTable(fields, true)),
    h("div", {class: "schema-sections"}, collections.map(c => schemaCollectionPanel(c))));
}

// One collection: what is in it, which findings sit on it, and a live,
// masked sample of its chunks. The question this answers is "what is actually
// in here, and which of it matters" — without running an assessment.
async function collectionView(storeId, collection, schema) {
  let findings = [];
  let findingsError = "";
  try {
    const result = await api(`/admin/findings?${new URLSearchParams({
      store: storeId, collection: collection.name, limit: "200"})}`);
    findings = result.findings || [];
  } catch (e) {
    findingsError = unavailableReason(e);
  }
  const labels = {};
  for (const f of findings) {
    for (const [label, n] of Object.entries(((f.evidence || {}).label_counts) || {})) {
      labels[label] = (labels[label] || 0) + Number(n || 0);
    }
  }
  const worst = findings.reduce((w, f) => severityMeets(f.severity, w) ? f.severity : w, "info");

  // The way back to the store's collections is the page header's.
  return h("div", {},
    kpiGrid("",
      metric("Vectors", number(collection.count), collection.dimension ? `${collection.dimension} dimensions` : ""),
      metric("Metadata keys", number(collection.metadata_key_count),
             collection.metadata_complete ? "complete sample" : `${number(collection.sample_size)} sampled`),
      metric("Findings", number(findings.length), findings.length ? `worst ${String(worst).toUpperCase()}` : "none recorded"),
      metric("Labels observed", Object.keys(labels).length ? Object.entries(labels)
        .sort((a, b) => b[1] - a[1]).map(([l, n]) => `${l} ${number(n)}`).join(" · ") : "None",
        "chunks by label, from findings")),
    panel("Findings in this collection", findingsError
      ? unavailableState(findingsError, "Findings are read from recorded scan history.")
      : findings.length
        ? compactFindingsTable(findings, storeId)
        : emptyState("No finding has been recorded on this collection.",
                     can("operator") ? {action: () => goTo("assess", {store: storeId}), actionLabel: "Run an assessment"} : {})),
    panel("Sample chunks", liveSamplePanel(storeId, collection.name)),
    schemaCollectionPanel(collection, {title: "Metadata fields"}));
}

// Findings where the scope is already known: severity, what, case, and the
// chunks behind it. The full table with its evidence chips is in History.
function compactFindingsTable(findings, storeId) {
  return table(["Severity", "Finding", "Case", "Chunks", ""], findings.map(f => {
    const refs = chunkRefs(f);
    return h("tr", {},
      h("td", {}, badge(f.severity)),
      h("td", {},
        h("button", {class: "link strong", type: "button", onclick: () => openFinding(f)}, f.title || f.id),
        h("div", {class: "tag-row"}, h("span", {class: "tag", title: f.category || null}, f.category ? categoryLabel(f.category) : "uncategorized"),
          f.suppressed ? stateChip("medium", "suppressed") : "")),
      h("td", {}, caseBadge((f.case || {}).state)),
      h("td", {}, refs.length
        ? h("div", {class: "tag-row chunk-refs"}, refs.slice(0, 3).map(r => h("button", {class: "link mono", type: "button",
            onclick: () => openChunk({store: f.store, collection: f.collection, chunkId: r.chunkId, finding: f})},
            r.chunkId)), refs.length > 3 ? h("span", {class: "sub"}, `+${refs.length - 3}`) : "")
        : h("span", {class: "sub"}, "none recorded")),
      h("td", {}, h("button", {class: "btn small", type: "button", onclick: () => openFinding(f)},
        icon("eye"), "Open")));
  }));
}

// A window over the collection, classified now and masked. Rows are marked
// "live" because they are not findings and nothing about them is recorded.
function liveSamplePanel(storeId, collectionName, {limit = 25} = {}) {
  const box = h("div", {});
  const columns = ["Chunk", "Labels", "Detectors", "Matches", "Preview (masked)"];
  // Rows are appended a window at a time, so the body is written directly.
  const sample = dataTable(columns);
  const tbody = sample.tbody;
  const status = h("p", {class: "sub"}, "");
  let offset = 0;
  let exhausted = false;
  const more = h("button", {class: "btn small", type: "button", onclick: () => load()}, icon("play"), `Sample ${limit} chunks`);

  async function load() {
    more.disabled = true;
    status.textContent = "Classifying a window of the collection…";
    try {
      const body = await api(`/stores/${encodeURIComponent(storeId)}/collections/${encodeURIComponent(collectionName)}` +
                             `/sample?${new URLSearchParams({limit: String(limit), offset: String(offset)})}`);
      for (const c of body.chunks || []) {
        tbody.append(h("tr", {},
          h("td", {}, h("button", {class: "link mono", type: "button",
            onclick: () => openChunk({store: storeId, collection: collectionName, chunkId: c.chunk_id})}, c.chunk_id)),
          h("td", {}, c.labels.length
            ? h("div", {class: "tag-row"}, c.labels.map(l => h("span", {class: `tag sev-${spanTone(l)}`}, l)))
            : h("span", {class: "sub"}, "none")),
          h("td", {}, (c.detectors || []).join(", ") || "-"),
          h("td", {}, number(c.matches), c.disputed ? h("span", {class: "sub"}, " · disputed") : ""),
          h("td", {class: "mono sub"}, c.preview || "(no text)")));
      }
      labelCells(columns, [...tbody.children]);
      offset = body.next_offset;
      exhausted = body.exhausted;
      status.textContent = `${plural(offset, "chunk")} sampled so far · ${number(body.sensitive)} sensitive in this window` +
        (exhausted ? " · end of collection" : "") + `. ${body.note || ""}`;
      more.textContent = "";
      more.append(icon("play"), exhausted ? "Nothing more to sample" : `Sample ${limit} more`);
      more.disabled = exhausted;
    } catch (e) {
      status.textContent = "";
      box.replaceChildren(e.status === 409
        ? unavailableState(unavailableReason(e), "This store cannot be sampled.")
        : errorState(unavailableReason(e), load));
    }
  }

  box.append(
    statusLine("A live window over the collection, masked. It records nothing and is not an assessment.", "info"),
    sample.node,
    h("div", {class: "bar"}, more, status));
  return box;
}

// On the collection's own page the page is already named for it, so the
// panel is titled for what it holds instead.
function schemaCollectionPanel(collection, {title = collection.name} = {}) {
  const fields = collection.metadata_fields || [];
  return panel(title, h("div", {},
    h("div", {class: "schema-summary"},
      h("span", {class: "tag"}, `${number(collection.count)} vectors`),
      h("span", {class: "tag"}, `${number(collection.metadata_key_count)} metadata keys`),
      h("span", {class: "tag"}, collection.metadata_complete ? "complete sample" : `${number(collection.sample_size)} sampled`),
      collection.dimension ? h("span", {class: "tag"}, `${collection.dimension} dimensions`) : ""),
    Object.keys(collection.metadata || {}).length ? h("details", {class: "evidence-data"}, h("summary", {}, icon("code"), "Collection metadata"), jsonBlock(collection.metadata)) : "",
    metadataFieldsTable(fields, false)));
}

function metadataFieldsTable(fields, aggregate) {
  const rows = fields || [];
  return table(
    aggregate ? ["Field", "Count", "Collections", "Types"] : ["Field", "Count", "Coverage", "Types", "Top values"],
    rows.map(f => aggregate ? h("tr", {},
      h("td", {class: "mono"}, f.path),
      h("td", {}, number(f.count)),
      h("td", {}, number(f.collection_count)),
      h("td", {}, (f.types || []).join(", ") || "-")) : h("tr", {},
      h("td", {class: "mono"}, f.path),
      h("td", {}, number(f.count)),
      h("td", {}, `${Math.round(Number(f.coverage || 0) * 100)}%`),
      h("td", {}, (f.types || []).join(", ") || "-"),
      h("td", {}, (f.top_values || []).slice(0, 4).map(v => h("span", {class: "tag"}, `${shortValue(v.value)} (${number(v.count)})`)))))
  );
}

// The lifecycle the product actually runs, shown as a stepper so the next action
// is named. Stages are derived from real state; nothing here advances on hope.
// ----------------------------------------------------------------- crypto ---
// Cryptographic posture, read from a saved audit. The state vocabulary is the
// backend's (crypto/states.py) plus "not run" for a check the audit never
// recorded. The state that matters most here is `not_observable`: the store's
// interface cannot answer, which bounds what can be seen and is never a
// failure. It is drawn neutral with a dashed outline, so it cannot be read as
// the red of an observed exposure or the amber of "go and check this".
const CRYPTO_STATE = {
  verified: {tone: "ok", glyph: "sev-ok", text: "Verified"},
  protected_representation: {tone: "ok", glyph: "sev-ok", text: "Protected representation"},
  observed_exposure: {tone: "critical", glyph: "sev-critical", text: "Observed exposure"},
  not_verified: {tone: "medium", glyph: "sev-medium", text: "Not verified"},
  not_observable: {tone: "info", glyph: "eye-off", text: "Not observable"},
  not_supported: {tone: "info", glyph: "eye-off", text: "Not supported"},
  outside_connector_scope: {tone: "info", glyph: "eye-off", text: "Outside connector scope"},
  not_applicable: {tone: "info", glyph: "sev-na", text: "Not applicable"},
  not_run: {tone: "unknown", glyph: "sev-notrun", text: "Not run"},
};

// The order the layers are read in. A layer the read model leaves out is still
// drawn, saying so: a missing layer must not read as a layer with no problems.
const CRYPTO_LAYERS = [
  ["transport", "Transport"],
  ["storage", "Storage encryption"],
  ["data", "Field and data-level protection"],
  ["retrieval", "Retrieval exposure"],
];

// The posture policies every audit evaluates for crypto checks. None of them
// fires on "not observable": a property the store does not expose is not a
// disabled one.
const CRYPTO_POLICIES = {
  "at-rest-encryption-not-disabled": {check: "at_rest_encryption", severity: "high",
    when: "The database reports encryption at rest disabled"},
  "tls-enforced": {check: "transport_tls_enforcement", severity: "high",
    when: "The store accepts a plaintext connection"},
  "verify-tls-certificates": {check: "tls_certificate_verification", severity: "medium",
    when: "TLS is used without verifying the server certificate"},
  "pan-rendered-unreadable": {check: "pan_representation", severity: "critical",
    when: "A full, readable PAN is stored"},
  "protection-applied-consistently": {check: "data_representation", severity: "high",
    when: "A field mixes protected and plaintext values"},
};

const TECHNICAL_RESULT = {
  passed: {tone: "ok", text: "Passed"},
  failed: {tone: "critical", text: "Failed"},
  inconclusive: {tone: "medium", text: "Inconclusive"},
  not_run: {tone: "unknown", text: "Not run"},
};

// A check the audit did not run has no state to report, whatever state the
// record carries for bookkeeping.
function cryptoStateKey(state, outcome) {
  if (outcome === "not_run" || outcome === "skipped") return "not_run";
  return CRYPTO_STATE[state] ? state : "not_verified";
}

function cryptoStateText(state, outcome) {
  return CRYPTO_STATE[cryptoStateKey(state, outcome)].text;
}

function cryptoBadge(key, tone, text) {
  const meta = CRYPTO_STATE[key] || CRYPTO_STATE.not_verified;
  return h("span", {class: `badge crypto-chip crypto-${key.replace(/_/g, "-")} sev-${tone || meta.tone}`,
                    dataset: {state: key}},
    icon(meta.glyph), text || meta.text);
}

// "Not supported" is narrower than "not observable": the database has no
// interface that reports the property at all, whatever the configuration.
// It is a limit of the product being assessed, never a failure, and it comes
// with the evidence a person can supply instead. Reads a read-model row
// (details) or a check outcome (coverage) alike.
function cryptoSupport(record) {
  const d = (record && (record.details || record.coverage)) || {};
  const notSupported = d.support === "not_supported" ||
    (d.capability_limit === true && record?.outcome === "unsupported");
  return {
    notSupported,
    database: d.database || "",
    evidence: Array.isArray(d.evidence_to_supply) ? d.evidence_to_supply : [],
    documented: d.documented_default && d.documented_default.text ? d.documented_default : null,
    sources: Array.isArray(d.sources) ? d.sources : [],
  };
}

function recordStateKey(record) {
  if (cryptoSupport(record).notSupported && !["not_run", "skipped"].includes(record.outcome)) {
    return "not_supported";
  }
  return cryptoStateKey(record.crypto_state ?? (record.coverage || {}).crypto_state, record.outcome);
}

// The chip for a row or an outcome, naming the database when it is the
// database that cannot answer.
function recordChip(record) {
  const support = cryptoSupport(record);
  if (recordStateKey(record) === "not_supported") {
    return cryptoBadge("not_supported", "",
      support.database ? `Not supported by ${support.database}` : "Not supported");
  }
  return cryptoChip(record.crypto_state ?? (record.coverage || {}).crypto_state, record.outcome);
}

function domainOf(url) {
  return String(url || "").replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0].replace(/^www\./, "");
}

// Only http(s) becomes a link; anything else is shown as text.
function sourceLink(url, label) {
  if (!/^https?:\/\//i.test(String(url || ""))) return h("span", {class: "mono"}, String(url || ""));
  return h("a", {href: url, target: "_blank", rel: "noopener noreferrer"}, label || domainOf(url));
}

// What to supply when the database cannot show the property, and what the
// vendor documents. The documentation is context: it is labelled as such and
// never turns the state into a pass.
// The caveat that qualifies a one-sentence reason (for example, that readable
// through the database is not the same as unencrypted on disk). It travels in
// details or coverage as `note` and is always shown beside the reason: in
// full on a criterion card, as an inline tip on the Crypto table, where the
// same caveat would otherwise repeat on every row.
function cryptoNote(record, {tip = false} = {}) {
  const note = ((record && (record.details || record.coverage)) || {}).note;
  if (!note) return null;
  return tip
    ? h("span", {class: "crypto-note crypto-note-tip"}, tooltip(String(note)))
    : h("p", {class: "crypto-note"}, icon("info"), String(note));
}

function cryptoSupportBlock(record, {fold = false} = {}) {
  const info = cryptoSupport(record);
  if (!info.evidence.length && !info.documented && !info.sources.length) return null;
  // On the Crypto table the block is folded under one line, so a row stays
  // one row; the Criteria cards keep it open.
  const wrap = (...children) => fold
    ? h("details", {class: "crypto-why crypto-support"},
        h("summary", {}, icon("file"), info.evidence.length
          ? `Evidence you can supply instead (${number(info.evidence.length)})` : "Vendor documentation"),
        ...children)
    : h("div", {class: "crypto-support"}, ...children);
  return wrap(
    info.evidence.length
      ? h("div", {},
          fold ? null : h("div", {class: "metric-k"}, "Evidence you can supply instead"),
          h("ul", {class: "crypto-evidence-list"}, info.evidence.map(text => h("li", {}, text))))
      : null,
    info.documented
      ? h("p", {class: "crypto-documented"},
          h("span", {class: "tag crypto-doc-tag"}, "documented, not verified here"),
          ` Vendor documentation: ${info.documented.text}`,
          info.documented.source_url ? [" (", sourceLink(info.documented.source_url), ")"] : null)
      : null,
    info.sources.length
      ? h("details", {class: "evidence-data crypto-sources"},
          h("summary", {}, icon("file"), `Sources (${info.sources.length})`),
          h("ul", {class: "crypto-detail-list"}, info.sources.map(url => h("li", {}, sourceLink(url, url)))))
      : null);
}

// One chip for every crypto state in the console: this screen, the criteria
// cards, and run results. The label is always text; colour only repeats it.
function cryptoChip(state, outcome) {
  const key = cryptoStateKey(state, outcome);
  // Readable full PAN, or protection applied inconsistently, fails; sensitive
  // plaintext whose significance depends on risk is an exposure for review.
  const tone = key === "observed_exposure" && outcome && outcome !== "failed" ? "high" : "";
  return cryptoBadge(key, tone);
}

function technicalChip(result) {
  return toneChip(TECHNICAL_RESULT, result);
}

// Fallback words for a relationship the server did not label. The server's
// relationship_label wins when it is sent.
const RELATIONSHIP_LABEL = {
  direct: "Direct", risk_based: "Risk-based", addressable: "Addressable", control_evidence: "Control evidence",
  direct_where_pan: "Direct where PAN is present", supporting: "Supporting evidence only",
  audit_component: "Assessed in a required audit",
};

function relationshipTag(row) {
  const kind = String(row.relationship || "unstated").replace(/_/g, "-");
  return h("span", {class: `tag rel-tag rel-${kind}`},
    row.relationship_label || RELATIONSHIP_LABEL[row.relationship] || humanize(row.relationship) || "Unstated");
}

// An artifact type's name, from the pack's vocabulary where it has one.
function evidenceName(name) {
  return name ? evidenceInfo(name).label : "";
}

// The coverage vocabulary the read model's statement uses (crypto/view.py
// COVERAGE_BUCKETS), worst first. Only "verified" was observed to be
// protected; the rest are drawn so none of them can pass for it.
const COVERAGE_BUCKET = {
  exposure: {tone: "high", glyph: "sev-high", text: "Exposure observed", basis: "observed"},
  unknown: {tone: "medium", glyph: "sev-medium", text: "Not established", basis: "unknown"},
  not_checked: {tone: "unknown", glyph: "sev-notrun", text: "Not checked", basis: "not_checked"},
  not_observable: {tone: "info", glyph: "eye-off", text: "Not observable", basis: "unknown"},
  declared: {tone: "medium", glyph: "file", text: "Declared, not verified", basis: "declared"},
  verified: {tone: "ok", glyph: "sev-ok", text: "Verified", basis: "observed"},
  not_applicable: {tone: "info", glyph: "sev-na", text: "Not applicable", basis: "observed"},
};
const COVERAGE_BASIS = [
  ["observed", "Observed", "verified, exposure seen, or nothing to protect"],
  ["declared", "Declared, not verified", "configuration or vendor documentation only"],
  ["unknown", "Unknown or not observable", "the store could not answer, or did not"],
  ["not_checked", "Not checked", "skipped, excluded or opt-in"],
];

function coverageBadge(bucket, text) {
  const meta = COVERAGE_BUCKET[bucket] || COVERAGE_BUCKET.unknown;
  const outline = bucket === "not_observable" ? " crypto-not-observable"
    : bucket === "not_checked" ? " crypto-not-run" : bucket === "declared" ? " crypto-declared" : "";
  return h("span", {class: `badge crypto-chip crypto-cov-chip sev-${meta.tone}${outline}`,
                    dataset: {bucket}},
    icon(meta.glyph), text || meta.text);
}

// A layer statement's sentence without its "Transport: " lead, which the card
// already carries as its heading.
function coverageSentenceOf(statement) {
  const text = String(statement?.text || "");
  const lead = `${statement?.title || ""}: `;
  const rest = text.startsWith(lead) ? text.slice(lead.length) : text;
  return rest ? rest[0].toUpperCase() + rest.slice(1) : "";
}

// A 404 whose detail is FastAPI's bare "Not Found" means the route does not
// exist on this server: the console is newer than the API it is talking to.
// Any other 404 is the API saying a named thing is missing.
function routeMissing(e) {
  return e?.status === 404 && /^not found\.?$/i.test(String(e.message || "").trim());
}

function staleServerDetail(path) {
  return `The API server answered ${path} with 404 Not Found: it does not have this route, which ` +
    "usually means the server was started from an older checkout than this console. Restart " +
    "`vecshield-platform serve` from the current checkout, then retry.";
}

async function renderCrypto() {
  await loadCore();
  const box = h("div", {class: "estate-view crypto-page"});
  // "scope=estate" (the Overview's link for several blocked stores) opens the
  // estate matrix rather than the store last used.
  const scope = param("scope") === "estate" && !param("store") ? {id: "", remembered: false} : scopedStore();
  const store = selectInput([["", state.stores.length > 1 ? "All stores (estate)" : "Choose a store"],
                             ...state.stores.map(s => [s.store_id, s.store_id])], scope.id,
                            {id: "crypto-store"});
  const estateBox = h("div", {class: "crypto-estate-slot"});
  const out = h("div", {class: "crypto-store-slot"});
  let estate = null;
  let estateError = null;

  async function loadEstate() {
    if (state.stores.length < 2) return;
    estateBox.replaceChildren(loadingState("Reading the estate's crypto coverage"));
    try {
      estate = await api("/admin/crypto-estate");
      estateError = null;
    } catch (e) {
      estate = null;
      estateError = e;
    }
    drawEstate();
  }

  function pick(id) {
    store.value = id;
    setParams({store: id, audit: "", layer: "", scope: ""});
    drawEstate();
    draw();
    out.scrollIntoView?.({block: "start", behavior: "smooth"});
  }

  function drawEstate() {
    if (state.stores.length < 2) { estateBox.replaceChildren(); return; }
    if (estateError) {
      const missing = routeMissing(estateError);
      estateBox.replaceChildren(panel("Crypto coverage across the estate", h("div", {},
        unavailableState(missing ? "This server does not serve the estate summary."
                                 : `The estate summary could not be read: ${unavailableReason(estateError)}`,
          missing ? `${staleServerDetail("GET /admin/crypto-estate")} Each store can still be read on its own below.`
                  : "Each store can still be read on its own; choose one above."),
        h("button", {class: "btn small", type: "button", onclick: loadEstate}, icon("refresh"), "Retry"))));
      return;
    }
    if (!estate) return;
    const matrix = cryptoEstateMatrix(estate, store.value, pick);
    const list = estate.stores || [];
    // With a store open, the estate folds to one line of counts so the store
    // leads; with none chosen, the matrix is the page.
    const blocked = list.filter(r => (r.gate || {}).decision === "block").length;
    const never = list.filter(r => r.state === "never_assessed").length;
    const exposed = list.filter(r => ((r.statement || {}).totals || {}).exposure > 0).length;
    const facts = [plural(list.length, "store"),
                   exposed ? `${number(exposed)} with an exposure observed` : "",
                   blocked ? `${number(blocked)} the gate would block` : "",
                   never ? `${number(never)} never assessed` : ""].filter(Boolean).join(" · ");
    estateBox.replaceChildren(store.value
      ? h("details", {class: "panel crypto-estate-fold"},
          h("summary", {}, icon("layers"), h("span", {class: "strong"}, "All stores"),
            h("span", {class: "sub"}, facts), h("span", {class: "crypto-estate-open sub"}, "Compare")),
          h("div", {class: "panel-body"}, matrix))
      : panel("Crypto coverage across the estate", matrix));
  }

  async function draw() {
    if (!store.value) {
      out.replaceChildren(state.stores.length > 1
        ? ""
        : panel("Crypto posture", state.stores.length
          ? emptyState("Choose a store to read its saved audit's crypto posture.")
          : emptyState("No stores are registered. Add one, then run an audit.",
                       {action: () => goTo("stores"), actionLabel: "Go to Stores"})));
      return;
    }
    const asked = store.value;
    out.replaceChildren(loadingState("Reading the saved audit's crypto posture"));
    const query = param("audit") ? `?${new URLSearchParams({audit_id: param("audit")})}` : "";
    try {
      const model = await api(`/stores/${encodeURIComponent(asked)}/crypto-posture${query}`);
      if (store.value !== asked) return;
      const gate = cryptoGatePanel(asked);
      out.replaceChildren(cryptoPostureView(model, asked, gate));
      await gate.ready;
      // Arriving from an audit's "Release gate" step lands on the gate.
      if (param("section") === "gate") document.getElementById("release-gate")?.scrollIntoView?.({block: "start"});
    } catch (e) {
      if (store.value !== asked) return;
      out.replaceChildren(cryptoUnavailable(e, asked, draw));
    }
  }

  store.addEventListener("change", () => {
    setParams({store: store.value, audit: "", layer: "", scope: ""});
    drawEstate();
    draw();
  });
  // The store is the screen's scope, so it sits in the header; Reload is a
  // secondary control beside it, not a second primary action.
  box.append(pageHeader("crypto", undefined,
    h("button", {class: "btn", type: "button", onclick: () => { loadEstate(); draw(); }}, icon("refresh"), "Reload"),
    {scope: fieldTip("Store", store, "Read from this store's most recent saved audit. Nothing is scanned.")}));
  box.append(pageIntro("crypto", {
    facts: [
      ["Stores", number(state.stores.length), "registered"],
      ["Summary", "Counts only", "no crypto score"],
    ],
    actions: [
      can("operator") ? introAction("Run an assessment", "shield", () => goTo("assess", store.value ? {store: store.value} : {})) : null,
      introAction("Criteria for this store", "check", () => goTo("criteria", store.value ? {store: store.value} : {})),
      introAction("What each framework requires", "layers", () => goTo("frameworks")),
    ],
  }));
  box.append(rememberedStoreNote(scope));
  if (param("audit")) {
    box.append(statusLine(`Showing saved audit ${param("audit")}, not the latest.`, "medium"));
  }
  box.append(estateBox, out);
  await Promise.all([loadEstate(), draw()]);
  return box;
}

// One row per store, one cell per layer: the headline of what its latest
// audit established there. A store never assessed is a row that says so.
function cryptoEstateMatrix(estate, selected, onPick) {
  const rows = estate.stores || [];
  const heads = CRYPTO_LAYERS.map(([id, title]) => [id, {transport: "Transport", storage: "At rest",
    data: "Field and data", retrieval: "Retrieval"}[id] || title]);
  const cell = (statement, id) => {
    const layer = (statement?.layers || []).find(l => l.layer === id);
    if (!layer) return h("td", {class: "crypto-estate-cell"}, coverageBadge("not_checked", "Not reported"));
    // The chip is the headline; the full sentence is one hover away.
    return h("td", {class: "crypto-estate-cell", title: layer.text || ""}, coverageBadge(layer.headline));
  };
  const body = rows.map(row => {
    const on = row.store_id === selected;
    const name = h("button", {class: "link mono strong", type: "button",
                              "aria-current": on ? "true" : "false",
                              onclick: () => onPick(row.store_id)}, row.store_id);
    if (row.state !== "assessed") {
      const never = row.state === "never_assessed";
      return h("tr", {class: `crypto-estate-row${on ? " is-selected" : ""}`, dataset: {store: row.store_id}},
        h("th", {scope: "row"}, name, h("div", {class: "sub"}, row.kind || "")),
        h("td", {colspan: heads.length + 1, class: "crypto-estate-gap"},
          never
            ? stateChip("unknown", "Never assessed")
            : stateChip("medium", "Unavailable"),
          h("span", {class: "sub"}, never
            ? " Nothing known yet; not a clean result."
            : ` ${row.reason || "Its latest saved audit could not be read."}`),
          never && can("operator")
            ? h("button", {class: "btn small", type: "button", onclick: () => goTo("assess", {store: row.store_id})},
                icon("shield"), "Run an audit")
            : ""));
    }
    const gate = row.gate || {};
    return h("tr", {class: `crypto-estate-row${on ? " is-selected" : ""}`, dataset: {store: row.store_id}},
      h("th", {scope: "row"}, name,
        h("div", {class: "sub"}, row.kind || "", row.assessed_at ? [" · ", relativeTime(row.assessed_at)] : "")),
      heads.map(([id]) => cell(row.statement, id)),
      h("td", {class: "crypto-estate-cell"}, gate.decision
        ? gateDecisionChip(gate.decision)
        : stateChip("unknown", "Not evaluated", {title: gate.reason || ""})));
  });
  // A wide matrix that scrolls inside its own region (it never turns into
  // cards), so the wrap is not a table-wrap.
  return h("div", {class: "crypto-estate"},
    table(["Store", ...heads.map(([, label]) => label), "Release gate"], body, {
      wrapClass: "crypto-estate-scroll", tableClass: "crypto-estate-table",
      wrapAttrs: {role: "region", "aria-label": "Crypto coverage by store", tabindex: "0"},
      empty: emptyState("No stores are registered.")}),
    h("p", {class: "sub crypto-estate-lede"},
      "Latest saved audit per store. Verified only when every check in the layer was. ",
      estate.note ? tooltip(estate.note) : ""));
}

// What the audit established, one tile per layer. The tiles double as the
// switch for the rows below. A tile's chip is the read model's headline for
// the layer, worst first, so one verified row never makes a mixed layer read
// Verified. An older server that sends no statement gets a line saying so.
const CRYPTO_TILE_TITLE = {transport: "Transport", storage: "At rest", data: "Field and data", retrieval: "Retrieval"};

function cryptoAtRestLine(model, rows) {
  const coverage = model.coverage || {};
  const atRestRows = (rows || []).filter(row => row.check === "at_rest_encryption");
  const unsupported = atRestRows.length > 0 && atRestRows.every(row => cryptoSupport(row).notSupported);
  return cryptoCoverageText(coverage.at_rest, {unsupported, total: coverage.collections_total});
}

// The caveats that qualify every count on the page, said once and folded.
function cryptoWhy(model) {
  const statement = (model.coverage || {}).statement || {};
  const lines = [model.note || "No crypto score. Counts describe what the connector could observe.",
                 statement.note, ...(model.statements || [])].filter(Boolean);
  return h("details", {class: "crypto-why"},
    h("summary", {}, icon("info"), "Why?"),
    h("ul", {class: "crypto-why-list"}, lines.map(text => h("li", {}, text))));
}

function cryptoCoveragePanel(model, onLayer, extras = []) {
  const coverage = model.coverage || {};
  const statement = coverage.statement;
  const rows = (Array.isArray(model.layers) ? model.layers : []).flatMap(l => l.rows || []);
  const total = coverage.collections_total;
  const meta = h("span", {class: "crypto-cov-meta sub"},
      h("span", {class: "mono"}, model.audit_id || "audit unrecorded"), " · ",
      model.assessed_at ? h("span", {title: formatWhen(model.assessed_at)}, relativeTime(model.assessed_at))
                        : "time unrecorded",
      typeof total === "number" ? ` · ${plural(total, "collection")}` : "",
      " · ", h("span", {class: "mono"}, model.pack_version || "pack unknown"));
  const section = body => panel([icon("shield"), "Posture"], body, meta,
                                {className: "crypto-cov", label: "Crypto posture"});
  if (!statement || !Array.isArray(statement.layers)) {
    return section([
      statusLine("This server does not summarise crypto coverage. Read the rows below; " +
                 "a layer with no verified row was not verified.", "medium"),
      h("p", {class: "crypto-cov-basis sub"}, "At rest, by collection: ", cryptoAtRestLine(model, rows)),
      ...extras,
      h("div", {class: "crypto-cov-foot"}, cryptoWhy(model))]);
  }
  const byLayer = new Map(statement.layers.map(l => [l.layer, l]));
  const cards = CRYPTO_LAYERS.map(([id, title]) => {
    const layer = byLayer.get(id);
    const name = CRYPTO_TILE_TITLE[id] || title;
    const tile = (bucket, chip, ...lines) => h("button", {
      class: "crypto-cov-card", type: "button", "aria-pressed": "false",
      dataset: {layer: id, bucket}, title: layer?.text || "",
      onclick: () => onLayer(id)},
      h("span", {class: "crypto-cov-card-head"}, h("span", {class: "crypto-cov-title"}, name), chip),
      ...lines);
    if (!layer) {
      return tile("not_checked", coverageBadge("not_checked", "Not reported"),
        h("span", {class: "crypto-cov-text"}, "Nothing recorded; not verified"));
    }
    const sentence = coverageSentenceOf(layer);
    const same = sentence.toLowerCase() === (COVERAGE_BUCKET[layer.headline]?.text || "").toLowerCase();
    const where = layer.collections_with_exposure || [];
    return tile(layer.headline, coverageBadge(layer.headline),
      h("span", {class: "crypto-cov-text"}, plural(layer.rows, "row"), same ? "" : ` · ${sentence}`),
      id === "storage"
        ? h("span", {class: "crypto-cov-where"}, "Collections: ", cryptoAtRestLine(model, rows))
        : "",
      where.length ? h("span", {class: "crypto-cov-where"}, `Exposure in ${where.join(", ")}`) : "");
  });
  const all = h("button", {class: "crypto-cov-card crypto-cov-all", type: "button", "aria-pressed": "false",
                           dataset: {view: "all"}, onclick: () => onLayer("all")},
    h("span", {class: "crypto-cov-title"}, "All"),
    h("span", {class: "crypto-cov-text"}, plural(statement.rows, "row")));
  const basis = statement.by_basis || {};
  const node = section([
    h("div", {class: "crypto-cov-grid", role: "group", "aria-label": "Layers: choose one to list its rows"},
      cards, all),
    h("div", {class: "crypto-cov-foot"},
      h("dl", {class: "crypto-cov-basis"}, COVERAGE_BASIS.map(([key, label, hint]) =>
        h("div", {class: `crypto-cov-basis-item basis-${key.replace(/_/g, "-")}`, title: hint},
          h("dt", {}, label), h("dd", {}, number(basis[key] || 0))))),
      h("span", {class: "sub"}, "counts, not a score"),
      cryptoWhy(model)),
    ...extras]);
  node.cards = [...cards, all];
  return node;
}

function cryptoUnavailable(e, storeId, retry) {
  if (e.status === 409) {
    return panel("Crypto posture", emptyState(
      "No saved audit for this store yet. Crypto posture is read from a saved audit and " +
      "never scans: run an audit from New assessment first.",
      can("operator") ? {action: () => goTo("assess", {store: storeId}), actionLabel: "Run an audit"} : {}));
  }
  if (routeMissing(e)) {
    return panel("Crypto posture", h("div", {},
      unavailableState("This server does not serve crypto posture.",
        staleServerDetail(`GET /stores/${storeId}/crypto-posture`)),
      h("button", {class: "btn small", type: "button", onclick: retry}, icon("refresh"), "Retry")));
  }
  if (e.status === 404) {
    return panel("Crypto posture", h("div", {},
      unavailableState(unavailableReason(e),
        "The store or saved audit does not exist, or this server does not serve crypto posture."),
      h("button", {class: "btn small", type: "button", onclick: retry}, icon("refresh"), "Retry")));
  }
  return panel("Crypto posture", errorState(
    `GET /stores/${storeId}/crypto-posture failed: ${unavailableReason(e)}`, retry));
}

// ------------------------------------------------------------ crypto gate ---
// The release gate reads one saved audit plus evidence accepted for the store
// and returns a decision a pipeline acts on. It enforces nothing itself. The
// wording matters: "pass" means no gate rule held in this audit, which is not
// a statement about any regulation.
const GATE_DECISION = {
  block: {tone: "critical", text: "Block"},
  request_evidence: {tone: "medium", text: "Evidence needed"},
  warn: {tone: "low", text: "Warn"},
  pass: {tone: "ok", text: "No gate rule held in this audit"},
};

const GATE_CLI_EXITS = "exits 2 on block, 1 when evidence is needed, 0 on warn or when no rule held";

function gateDecisionChip(decision) {
  const meta = GATE_DECISION[decision] || {tone: "unknown", text: String(decision || "no decision")};
  const chip = stateChip(meta.tone, meta.text);
  chip.classList.add("gate-chip");
  chip.dataset.decision = decision || "";
  return chip;
}

function gateRequirement(item) {
  if (item == null) return "";
  if (typeof item === "string") return evidenceName(item);
  const requirement = evidenceName(item.requirement || "evidence");
  return item.criterion_id ? `${requirement} (${item.criterion_id})` : requirement;
}

function gateRuleItem(rule) {
  const status = rule.status || "not_triggered";
  const clears = rule.evidence_that_clears || [];
  const decisionClass = `gate-rule-${String(rule.decision || "none").replace(/_/g, "-")}`;
  return h("article", {class: `gate-rule gate-rule-${status.replace(/_/g, "-")} ${decisionClass}`,
                       dataset: {rule: rule.id || "", status}},
    h("div", {class: "gate-rule-head"},
      h("span", {class: "mono strong"}, rule.id || "rule"),
      status === "cleared"
        ? stateChip("ok", "cleared")
        : gateDecisionChip(rule.decision)),
    rule.description ? h("p", {class: "gate-rule-desc"}, rule.description) : null,
    (rule.reasons || []).length
      ? h("ul", {class: "gate-reasons"}, rule.reasons.map(text => h("li", {}, text)))
      : null,
    status === "cleared" && (rule.cleared_by || []).length
      ? h("p", {class: "gate-cleared"}, icon("check"),
          `Cleared by ${rule.cleared_by.map(gateRequirement).join(", ")}`)
      : null,
    status === "fired"
      ? (clears.length
          ? h("div", {class: "gate-clears"},
              h("span", {class: "metric-k"}, clears.length > 1 && rule.clears_with === "any"
                ? "Any one of these, once accepted, clears it" : "Evidence that would clear it"),
              h("ul", {}, clears.map(item => h("li", {}, gateRequirement(item)))),
              h("button", {class: "link", type: "button", onclick: () => goTo("evidence")},
                icon("file"), "Open the Evidence register"))
          : h("p", {class: "sub"},
              "No document clears this: it rests on what the audit observed, and only a change to the store does."))
      : null,
    rule.remediation ? h("p", {class: "sub"}, h("span", {class: "strong"}, "Remediation: "), rule.remediation) : null,
    rule.basis ? h("p", {class: "sub"}, h("span", {class: "strong"}, "Basis: "), rule.basis) : null);
}

// One line: the decision, what fired, and the policy switch. The rules, the
// evidence that clears them and the pipeline command are one click away.
function gateView(gate, {storeId, requiresAtRest, onToggle}) {
  const rules = gate.rules || [];
  const fired = rules.filter(r => r.status === "fired");
  const cleared = rules.filter(r => r.status === "cleared");
  const quiet = rules.filter(r => r.status !== "fired" && r.status !== "cleared");
  const toggle = h("input", {type: "checkbox", id: "gate-requires-at-rest", checked: requiresAtRest});
  toggle.addEventListener("change", () => onToggle(toggle.checked));
  const decision = gate.decision;
  const needed = gate.evidence_needed || [];
  return h("div", {class: "gate-body"},
    h("div", {class: "gate-head"},
      decision ? gateDecisionChip(decision)
               : stateChip("unknown", "No decision", {title: "The gate returned no decision for this audit."}),
      fired.length
        ? h("span", {class: "gate-fired"}, fired.map(r => r.description || r.id).join(" · "))
        : "",
      needed.length
        ? h("span", {class: "gate-needed"}, "Needs: ", needed.map(gateRequirement).join(", "), " ",
            h("button", {class: "link", type: "button", onclick: () => goTo("evidence")},
              icon("file"), "Evidence register"))
        : "",
      (gate.labels || []).length ? h("span", {class: "sub"}, `Data in scope: ${gate.labels.join(", ")}`) : "",
      h("label", {class: "check-row gate-toggle", for: "gate-requires-at-rest"}, toggle,
        h("span", {}, "Require encryption at rest"),
        tooltip("Re-evaluates the gate with that rule on. Not saved."))),
    h("details", {class: "crypto-why gate-more"},
      h("summary", {}, icon("list"), `Rules (${number(fired.length)} fired, ${number(cleared.length)} cleared)`),
      h("div", {class: "gate-more-body"},
        decision === "pass"
          ? h("p", {class: "sub"}, "No rule held against this audit and the evidence accepted for it. " +
              "Not a regulatory conclusion.")
          : null,
        fired.length ? h("div", {class: "gate-rules"}, fired.map(gateRuleItem)) : null,
        cleared.length ? h("div", {class: "gate-rules"}, cleared.map(gateRuleItem)) : null,
        quiet.length
          ? h("details", {class: "evidence-data"},
              h("summary", {}, icon("list"),
                `${number(quiet.length)} ${quiet.length === 1 ? "rule" : "rules"} not triggered`),
              h("div", {class: "gate-rules"}, quiet.map(gateRuleItem)))
          : null,
        gate.note ? h("p", {class: "sub"}, gate.note) : null,
        h("div", {class: "gate-cli"},
          h("code", {class: "gate-cli-line"},
            `vecshield-platform crypto-gate --store ${storeId}` +
            (requiresAtRest ? " --requires-at-rest-encryption" : "")),
          h("span", {class: "sub"}, `${GATE_CLI_EXITS}. Every pipeline evaluation is written to the audit log.`)))));
}

function cryptoGatePanel(storeId) {
  const body = h("div", {class: "crypto-line-v"}, loadingState("Evaluating the release gate"));
  let requiresAtRest = false;
  async function load() {
    body.replaceChildren(loadingState("Evaluating the release gate"));
    // Looking at the screen is not a release decision, so it is not written
    // to the audit log. Pipelines calling the gate are logged.
    const query = new URLSearchParams({record: "false"});
    if (param("audit")) query.set("audit_id", param("audit"));
    if (requiresAtRest) query.set("requires_at_rest_encryption", "true");
    const suffix = query.toString();
    try {
      const gate = await api(`/stores/${encodeURIComponent(storeId)}/crypto-gate${suffix ? `?${suffix}` : ""}`);
      body.replaceChildren(gateView(gate, {storeId, requiresAtRest,
        onToggle: value => { requiresAtRest = value; return load(); }}));
    } catch (e) {
      body.replaceChildren(e.status === 409
        ? emptyState("No saved audit to evaluate; run an audit from New assessment first.",
                     can("operator") ? {action: () => goTo("assess", {store: storeId}), actionLabel: "Run an audit"} : {})
        : unavailableState(unavailableReason(e), "The release gate could not be evaluated."));
    }
  }
  const node = h("div", {class: "crypto-line gate-panel", id: "release-gate", role: "group",
                         "aria-label": "Release gate"},
    h("span", {class: "crypto-line-k"}, "Release gate",
      tooltip("Decides from this audit and the evidence accepted for the store; enforces nothing itself.")),
    body);
  node.ready = load();
  return node;
}

// A rule's trigger, in words. The server sends a small structured condition;
// anything this does not recognise is shown as the raw condition, not dropped.
function gateWhenText(when) {
  if (!when) return "-";
  if (typeof when === "string") return when;
  const states = list => list.map(state => (CRYPTO_STATE[state]?.text || String(state).replace(/_/g, " ")).toLowerCase());
  const parts = [];
  const check = when.check ? checkLabel(when.check) : "";
  if (check && (when.outcomes || []).length) parts.push(`${check}: outcome ${when.outcomes.join(" or ")}`);
  else if (check && (when.states || []).length) parts.push(`${check}: ${states(when.states).join(" or ")}`);
  else if (check && (when.not_states || []).length) parts.push(`${check}: anything but ${states(when.not_states).join(" or ")}`);
  else if (check) parts.push(check);
  if ((when.labels_any || []).length) parts.push(`with ${when.labels_any.join(", ")} data present`);
  if (when.setting) parts.push(`when the "${String(when.setting).replace(/_/g, " ")}" setting is on`);
  const known = new Set(["check", "outcomes", "states", "not_states", "labels_any", "setting"]);
  const rest = Object.fromEntries(Object.entries(when).filter(([key]) => !known.has(key)));
  if (Object.keys(rest).length) parts.push(cryptoDetailText(rest));
  return parts.join(", ") || cryptoDetailText(when);
}

// The gate's rule catalog, as the server evaluates it.
async function cryptoGateRulesPanel() {
  let data;
  try {
    data = await api("/compliance/crypto-gate/rules");
  } catch (e) {
    return panel("Crypto gate rules", unavailableState(unavailableReason(e),
      "The rule catalog is served by the compliance API."));
  }
  const rules = Array.isArray(data?.rules) ? data.rules : [];
  return panel("Crypto gate rules", h("div", {},
    h("p", {class: "sub fw-lede"},
      "A pipeline asks the gate before a release; the gate decides from the store's saved audit " +
      "and the evidence accepted for it. Evidence clears a gap. It never clears an observed " +
      "failure, such as a readable full PAN or encryption at rest reported off."),
    rules.length
      ? table(["Rule", "Decision", "When it fires", "Evidence that clears it", "Basis"],
          rules.map(rule => h("tr", {dataset: {rule: rule.id || ""}},
            h("td", {}, h("div", {class: "mono strong"}, rule.id),
              rule.description ? h("div", {class: "sub"}, rule.description) : null,
              rule.remediation ? h("div", {class: "sub"}, `Remediation: ${rule.remediation}`) : null),
            h("td", {}, gateDecisionChip(rule.decision)),
            h("td", {}, gateWhenText(rule.when)),
            h("td", {}, (rule.evidence_that_clears || []).length
              ? h("ul", {class: "crypto-detail-list"},
                  rule.evidence_that_clears.map(item => h("li", {}, gateRequirement(item))))
              : h("span", {class: "sub"}, "Nothing — no document clears what the audit observed")),
            h("td", {class: "sub"}, rule.basis || "-"))))
      : emptyState("The server lists no gate rules."),
    h("p", {class: "sub"},
      h("code", {class: "gate-cli-line"}, "vecshield-platform crypto-gate --store <id>"),
      ` ${GATE_CLI_EXITS}.`)));
}

// The store's page, top to bottom: one panel with a tile per layer, the
// release gate and what changed, each a line; then the selected layer's rows;
// then the regulations those rows inform.
const CRYPTO_BUCKET_ORDER = ["exposure", "unknown", "not_checked", "not_observable", "declared", "verified", "not_applicable"];

function cryptoPostureView(model, storeId, gate = null) {
  const layers = cryptoLayers(model.layers);
  const rows = layers.flatMap(layer => layer.rows || []);
  const panels = layers.map((layer, index) => cryptoLayerPanel(layer, index, storeId));
  const statements = new Map((((model.coverage || {}).statement || {}).layers || []).map(l => [l.layer, l]));
  const ids = layers.map(l => l.layer);
  // Open on the layer that most needs reading; with no statement, show all.
  const worst = statements.size
    ? [...ids].sort((a, b) => CRYPTO_BUCKET_ORDER.indexOf(statements.get(a)?.headline ?? "not_checked") -
                              CRYPTO_BUCKET_ORDER.indexOf(statements.get(b)?.headline ?? "not_checked"))[0]
    : "all";
  let current = [...ids, "all"].includes(param("layer")) ? param("layer") : worst;
  const status = cryptoCoveragePanel(model, id => show(id),
    [gate || cryptoGatePanel(storeId), cryptoDriftPanel(model.drift)]);

  function show(id, {remember = true} = {}) {
    current = id;
    if (remember) setParams({layer: id === worst ? null : id});
    for (const card of status.cards || []) {
      const key = card.dataset.layer || card.dataset.view;
      card.setAttribute("aria-pressed", String(key === id));
      card.classList.toggle("is-on", key === id);
    }
    panels.forEach(p => { p.hidden = id !== "all" && p.dataset.layer !== id; });
  }
  show(current, {remember: false});

  return h("div", {class: "crypto"},
    status,
    h("section", {class: "crypto-layers", "aria-label": "Rows by layer"}, ...panels),
    cryptoRegulatoryPanel(model.regulatory, storeId, rows));
}

function cryptoLayers(list) {
  const given = Array.isArray(list) ? list : [];
  const known = CRYPTO_LAYERS.map(([id, title]) => {
    const found = given.find(layer => layer.layer === id);
    return found ? {...found, title: found.title || title} : {layer: id, title, rows: null};
  });
  const extra = given.filter(layer => !CRYPTO_LAYERS.some(([id]) => id === layer.layer));
  return [...known, ...extra];
}

// Counts, never a share: "38 verified, 4 unknown" must not be readable as
// complete, and a percentage would invite exactly that reading.
function cryptoCoverageText(atRest = {}, {unsupported = false, total} = {}) {
  const head = `${number(atRest.verified_encrypted)} verified encrypted · ` +
               `${number(atRest.verified_unencrypted)} verified unencrypted`;
  // When the database cannot report the property at all, the unknown
  // collections are unknown for that reason, and the line says so.
  if (unsupported) {
    const n = atRest.not_supported ?? atRest.unknown ?? total ?? 0;
    return `${head} · ${number(n)} not supported by the database`;
  }
  const extra = Number(atRest.not_supported) > 0
    ? ` · ${number(atRest.not_supported)} not supported by the database` : "";
  return `${head} · ${number(atRest.unknown)} unknown${extra}`;
}

function cryptoDriftPanel(drift) {
  const data = drift || {};
  const changes = data.changes || [];
  const compared = data.compared ?? Boolean(data.previous_audit_id);
  const line = (...body) => h("div", {class: "crypto-line crypto-drift-line", role: "group",
                                      "aria-label": "Changes since the previous audit"},
    h("span", {class: "crypto-line-k"}, "Since last audit"), h("div", {class: "crypto-line-v crypto-drift-body"}, ...body));
  if (!compared) {
    return line(h("span", {class: "sub"}, data.reason ||
      "No earlier saved audit to compare against."));
  }
  // Checks the earlier audit did not have are folded apart: after an upgrade
  // every check is "first observed", and those would bury a real change.
  const first = changes.filter(c => c.change === "new" || !c.before);
  const changed = changes.filter(c => !first.includes(c));
  const previous = data.previous_audit_id || "the previous audit";
  return line(
    changed.length
      ? h("ul", {class: "crypto-drift", title: `Compared with ${previous}`}, changed.map(cryptoDriftItem))
      : h("span", {class: "sub"}, `No state changed since ${previous}.`),
    first.length
      ? h("details", {class: "crypto-why crypto-drift-first"},
          h("summary", {}, icon("list"),
            `${number(first.length)} ${first.length === 1 ? "check" : "checks"} first observed in this audit`),
          h("ul", {class: "crypto-drift"}, first.map(cryptoDriftItem)))
      : null);
}

// A check the earlier audit did not have is "first observed", not a fix; one
// the later audit no longer records is not a fix either.
function cryptoDriftItem(change) {
  const name = `${change.label || checkLabel(change.check)}${change.collection ? ` (${change.collection})` : ""}`;
  const before = change.before;
  const after = change.after;
  let sentence;
  if (change.change === "new" || !before) {
    sentence = after ? `first observed as ${cryptoStateText(after.crypto_state, after.outcome).toLowerCase()}`
                     : "first observed";
  } else if (change.change === "absent" || !after) {
    sentence = `no longer recorded (was ${cryptoStateText(before.crypto_state, before.outcome).toLowerCase()})`;
  } else {
    sentence = `changed from ${cryptoStateText(before.crypto_state, before.outcome).toLowerCase()} ` +
               `to ${cryptoStateText(after.crypto_state, after.outcome).toLowerCase()}`;
  }
  return h("li", {class: "crypto-drift-item"},
    h("span", {}, h("span", {class: "strong"}, name), ` ${sentence}`),
    h("span", {class: "crypto-drift-chips", "aria-hidden": "true"},
      before ? cryptoChip(before.crypto_state, before.outcome) : "",
      before && after ? h("span", {class: "sub"}, "→") : "",
      after ? cryptoChip(after.crypto_state, after.outcome) : ""));
}

// Rows that say the same thing about several collections (one check, one
// state, one reason) are one line naming each collection; their details stay
// per collection. Store-scope rows are never merged.
function cryptoGroupRows(rows) {
  const groups = [];
  const byKey = new Map();
  for (const row of rows || []) {
    if (!row.collection) { groups.push({...row, members: [row]}); continue; }
    const key = JSON.stringify([row.check, recordStateKey(row), row.outcome, row.reason || "",
                                ((row.details || {}).note) || ""]);
    const found = byKey.get(key);
    if (found) { found.members.push(row); continue; }
    const group = {...row, members: [row]};
    byKey.set(key, group);
    groups.push(group);
  }
  return groups;
}

function cryptoLayerPanel(layer, index, storeId) {
  const rows = layer.rows;
  const groups = rows && rows.length ? cryptoGroupRows(rows) : [];
  const body = rows && rows.length
    ? table(["Control", "Collection", "State", "Reason", "Details"],
            groups.map(row => cryptoRow(row, storeId)))
    : unknownState("This audit's read model holds no rows for this layer.",
                   "Treat the layer as not verified; it is shown so its absence is visible.");
  const merged = rows ? rows.length - groups.length : 0;
  // A heading like every other panel's, so the four layers are reachable by
  // heading navigation and the step number centres on the title.
  return panel(
    [h("span", {class: "crypto-layer-n", "aria-hidden": "true"}, String(index + 1)), layer.title],
    body,
    h("span", {class: "sub"}, rows
      ? `${plural(rows.length, "row")}${merged ? `, identical ones grouped into ${plural(groups.length, "line")}` : ""}`
      : "not reported"),
    {className: `crypto-layer crypto-layer-${layer.layer}`, label: layer.title, dataset: {layer: layer.layer}});
}

function cryptoRow(row, storeId) {
  const members = row.members || [row];
  const collectionLink = name => h("button", {class: "link mono", type: "button",
    onclick: () => goTo("schema", {store: storeId, collection: name})}, name);
  return h("tr", {class: "crypto-row", dataset: {check: row.check || ""}},
    h("td", {},
      h("div", {class: "strong"}, row.label || checkLabel(row.check)),
      h("div", {class: "sub mono"}, [row.control, row.check].filter(Boolean).join(" · "))),
    h("td", {}, row.collection
      ? (members.length > 1
          ? h("ul", {class: "crypto-collections"}, members.map(m => h("li", {}, collectionLink(m.collection))))
          : collectionLink(row.collection))
      : h("span", {class: "sub"}, "Store scope")),
    h("td", {}, recordChip(row)),
    h("td", {class: "crypto-reason"},
      h("div", {}, row.reason || h("span", {class: "sub"}, "No reason recorded."), " ",
        cryptoNote(row, {tip: true})),
      cryptoSupportBlock(row, {fold: true})),
    h("td", {}, members.length > 1 ? cryptoGroupDetails(members) : cryptoDetails(row.details)));
}

function cryptoDetailEntries(details) {
  return Object.entries(details || {})
    .filter(([key, value]) => !CRYPTO_DETAIL_HIDDEN.has(key) && value !== undefined);
}

function cryptoGroupDetails(members) {
  const withDetails = members.filter(m => cryptoDetailEntries(m.details).length);
  if (!withDetails.length) return h("span", {class: "sub"}, "none");
  return h("details", {class: "evidence-data crypto-details"},
    h("summary", {}, icon("list"), `Details (${plural(withDetails.length, "collection")})`),
    withDetails.map(m => h("div", {class: "crypto-group-detail"},
      h("div", {class: "mono strong"}, m.collection),
      h("dl", {class: "kv crypto-kv"}, cryptoDetailEntries(m.details).flatMap(([key, value]) =>
        [h("dt", {}, prettyKey(key)), h("dd", {}, cryptoDetailValue(value))])))));
}

// Details are counts and configuration names. Masked PAN previews and the
// fraction behind a count are left out on purpose: the row is read by people
// without the reveal role, and a fraction reads as a score.
const CRYPTO_DETAIL_HIDDEN = new Set(["examples", "statement", "protected_fraction", "opt_in",
  // Shown in the reason cell, with the evidence to supply instead.
  "support", "database", "evidence_to_supply", "documented_default", "sources", "capability_limit",
  // Shown under the reason: the caveat that qualifies it.
  "note"]);

function cryptoDetailText(value) {
  if (value == null) return "unknown";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "number") {
    return Number.isInteger(value) ? number(value) : String(Math.round(value * 100) / 100);
  }
  if (Array.isArray(value)) return value.length ? value.map(cryptoDetailText).join(", ") : "none";
  if (typeof value === "object") {
    const parts = Object.entries(value).filter(([key]) => !CRYPTO_DETAIL_HIDDEN.has(key))
      .map(([key, item]) => `${prettyKey(key)} ${cryptoDetailText(item)}`);
    return parts.length ? parts.join(" · ") : "none";
  }
  return String(value);
}

function cryptoDetailValue(value) {
  if (!Array.isArray(value) || !value.some(item => item && typeof item === "object")) {
    return cryptoDetailText(value);
  }
  const shown = value.slice(0, 25);
  return h("ul", {class: "crypto-detail-list"},
    shown.map(item => {
      if (!item || typeof item !== "object") return h("li", {}, cryptoDetailText(item));
      const lead = item.path || item.collection || item.kind || "";
      const rest = Object.fromEntries(Object.entries(item).filter(([key]) =>
        !(lead && item[key] === lead && ["path", "collection", "kind"].includes(key))));
      return h("li", {}, lead ? h("span", {class: "mono"}, lead) : "",
        lead ? " — " : "", cryptoDetailText(rest));
    }),
    value.length > shown.length ? h("li", {class: "sub"}, `and ${number(value.length - shown.length)} more`) : "");
}

function cryptoDetails(details) {
  const entries = Object.entries(details || {})
    .filter(([key, value]) => !CRYPTO_DETAIL_HIDDEN.has(key) && value !== undefined);
  if (!entries.length) return h("span", {class: "sub"}, "none");
  return h("details", {class: "evidence-data crypto-details"},
    h("summary", {}, icon("list"), `Details (${entries.length})`),
    h("dl", {class: "kv crypto-kv"}, entries.flatMap(([key, value]) =>
      [h("dt", {}, prettyKey(key)), h("dd", {}, cryptoDetailValue(value))])));
}

function cryptoRegulatoryPanel(rows, storeId, layerRows = []) {
  const list = rows || [];
  return panel("Regulations",
    list.length
      ? table(["Framework", "Criteria", "Fallback evidence"], list.map(row => cryptoRegRow(row, storeId, layerRows)))
      : unavailableState("No regulatory mapping was returned for this audit."),
    h("span", {class: "sub"}, "technical results, not a compliance status",
      tooltip("Whether a criterion applies, and whether its evidence suffices, is settled on the Criteria screen.")),
    {className: "crypto-reg-panel"});
}

// A criterion whose checks all came back "not observable" reduces to a
// technical result of "not run". That is the engine's word; the reader needs
// to know the check did run and the store could not answer.
function unobservedOnly(checks, rows) {
  const relevant = (rows || []).filter(r => (checks || []).includes(r.check));
  return relevant.length > 0 && relevant.every(r =>
    ["not_observable", "not_supported"].includes(recordStateKey(r)));
}

// The database that cannot report a criterion's property, when that is why
// the criterion could not be decided from the run.
function unsupportedDatabase(checks, rows) {
  const hit = (rows || []).find(r => (checks || []).includes(r.check) && cryptoSupport(r).notSupported);
  return hit ? (cryptoSupport(hit).database || "this database") : "";
}

function regCoverageText(c, rows) {
  const db = unsupportedDatabase(c.checks, rows);
  if (db && (c.technical_coverage === "not_observable" ||
             (c.technical_result === "not_run" && unobservedOnly(c.checks, rows)))) {
    return `not supported by ${db}`;
  }
  return technicalCoverageText(c.technical_coverage);
}

function cryptoRegRow(row, storeId, layerRows = []) {
  const supporting = row.relationship === "supporting";
  const criteria = row.criteria || [];
  const fallback = [...new Set(criteria.flatMap(c => c.fallback_required || []))];
  return h("tr", {class: `crypto-reg-row${supporting ? " crypto-reg-supporting" : ""}`,
                  dataset: {framework: row.framework || ""}},
    h("td", {class: "crypto-reg-head"},
      h("button", {class: "link strong", type: "button", title: row.interpretation || "",
                   onclick: () => goTo("frameworks", {framework: row.framework})}, row.framework),
      " ", relationshipTag(row)),
    h("td", {}, supporting
      ? h("span", {class: "sub"}, "Context only: no encryption mandate.")
      : criteria.length
        ? h("ul", {class: "crypto-reg-criteria"}, criteria.map(c => h("li", {class: "crypto-reg-criterion",
                                                                        title: c.reason || ""},
            h("button", {class: "link mono", type: "button",
                         onclick: () => goTo("criteria", {store: storeId, framework: row.framework})},
              c.criterion_id),
            technicalChip(c.technical_result),
            h("span", {class: "sub"}, regCoverageText(c, layerRows),
              c.technical_result === "not_run" && c.technical_coverage !== "not_observable"
                && !unsupportedDatabase(c.checks, layerRows) && unobservedOnly(c.checks, layerRows)
                ? " · the check ran; the store does not expose this property"
                : ""))))
        : h("span", {class: "sub"}, "No criterion mapped.")),
    h("td", {}, fallback.length
      ? h("span", {class: "crypto-fallback", title: "Needed because the checks could not establish this property through the store."}, icon("file"), fallback.map(evidenceName).join(", "))
      : h("span", {class: "sub"}, "none")));
}

const ASSESS_STAGES = [
  ["scope", "Scope"], ["validate", "Validate"], ["run", "Run"],
  ["review", "Review"], ["verify", "Verify"], ["evidence", "Evidence"],
];

function lifecycleStepper(activeId, {note} = {}) {
  const activeIndex = ASSESS_STAGES.findIndex(([id]) => id === activeId);
  return stepList(ASSESS_STAGES.map(([, label]) => label), activeIndex, {
    label: "Assessment lifecycle", ariaCurrent: false,
    wrap: {tag: "nav", className: "stepper", after: note ? h("p", {class: "step-note"}, note) : ""},
    itemClass: state => `step step-${state}`,
    render: (label, state, index) => [
      h("span", {class: "step-dot"}, state === "done" ? icon("check") : String(index + 1)),
      h("span", {class: "step-label"}, label),
      state === "current" ? h("span", {class: "sr-only"}, "(current stage)") : ""],
  });
}

// ------------------------------------------------- the New assessment page ---
// One decision at a time: what to run, against what, with which active checks,
// then a single Run button that says exactly what it will do. The modes are in
// the order someone decides: the complete assessment first, then the two
// narrower ones, then the DPIA, which is a document built on an audit pass.
// Each states what it reads, what it writes, how heavy it is and what it
// leaves behind, so nobody has to run one to find out.
const RUN_MODES = [
  {id: "audit", label: "Full audit", glyph: "shield", flag: "Recommended",
   summary: "Every check on one store: sensitive data, integrity, posture, tenant isolation and your policies.",
   cost: "Heaviest",
   reads: "Every chunk in every collection, up to the chunk cap, plus the store's configuration.",
   writes: "Nothing in the store. Saves an audit to History; may send alerts to your configured sinks.",
   produces: "A saved audit. Findings, Crypto, Criteria and the release gate all read it."},
  {id: "posture", label: "Posture", glyph: "lock",
   summary: "Configuration only: network exposure, transport security, authentication and known vulnerabilities.",
   cost: "Light",
   reads: "Connection settings and the connector library's version. No chunk contents.",
   writes: "Nothing in the store. Records one scan in History.",
   produces: "Posture findings. Not a saved audit, so Criteria and Crypto do not read it."},
  {id: "integrity", label: "Integrity scan", glyph: "layers",
   summary: "RAG integrity for one collection: injected instructions, embedding anomalies and provenance gaps.",
   cost: "One collection",
   reads: "Every chunk in the collection you choose.",
   writes: "Nothing in the store. Records one scan in History.",
   produces: "Integrity findings for that collection. Not a saved audit."},
  {id: "dpia", label: "DPIA draft", glyph: "file",
   summary: "A GDPR Article 35 draft from a fresh audit pass: data categories, risks and the state of each safeguard.",
   cost: "Heaviest",
   reads: "Everything a full audit reads.",
   writes: "Nothing in the store and no saved audit. The draft stays with the run, under Runs.",
   produces: "A draft for your DPO to review and sign. It is not a legal determination."},
];
const RUN_MODE_IDS = RUN_MODES.map(m => m.id);

// A run's kind as a reader knows it; the API's names stay in the record.
const RUN_KIND_LABEL = {
  audit: "Full audit", pia: "DPIA draft", posture: "Posture check", scan_integrity: "Integrity scan",
  dsar_create: "Privacy request search", dsar_execute: "Privacy request erasure",
  erasure_execute: "Erasure", validate: "Connector validation", datasource_scan: "Data source scan",
  scan_classification: "Classification scan", erasure_plan: "Erasure plan",
};

// Active checks touch the store in ways a passive audit does not, so they are
// off unless someone switches them on for this run, only the full audit sends
// them, and they are deliberately not carried in the link.
const ACTIVE_PROBES = [
  {id: "probe-tls", field: "tls_probe", label: "TLS enforcement probe",
   short: "attempts a credential-free plaintext connection",
   does: "Opens one connection to the store's endpoint without TLS and without credentials, to see whether plaintext is refused where the store's own settings cannot say.",
   effect: "One extra connection attempt, which may appear in the store's access logs."},
  {id: "probe-retrieval", field: "retrieval_probe", label: "Retrieval exposure probe",
   short: "replays stored vectors as queries (read-only)",
   does: "Replays a sample of vectors already in each collection as similarity queries and classifies what comes back: what a query client can read.",
   effect: "Read-only, but adds query load: about 20 queries per collection."},
];

function runModeOf(id) {
  return RUN_MODES.find(m => m.id === id) || RUN_MODES[0];
}

async function renderAssess() {
  await loadCore();
  const box = h("div", {class: "assess-view"});
  let mode = RUN_MODE_IDS.includes(param("mode")) ? param("mode") : "audit";
  const store = selectInput([["", "Choose a store"],
                             ...state.stores.map(s => [s.store_id, s.store_id]),
                             ["__all__", "All stores, one after another"]],
                            param("store"), {id: "run-store"});
  // Integrity runs against one collection, picked from the store's schema.
  const collection = selectInput([["", "Choose a store first"]], "", {id: "run-collection"});
  let wantedCollection = param("collection");
  const maxChunks = textInput(param("max", ""), {type: "number", min: "1", id: "run-cap",
                                                 placeholder: "No cap", inputmode: "numeric"});
  const probeInputs = Object.fromEntries(ACTIVE_PROBES.map(p =>
    [p.field, h("input", {type: "checkbox", id: p.id, class: "probe-input"})]));
  const probes = () => Object.fromEntries(ACTIVE_PROBES
    .filter(p => probeInputs[p.field].checked).map(p => [p.field, true]));

  // Where the run stands, in one line above the Run bar. The numbered steps
  // of the form already show the path, so this says only what is happening
  // now and what to do next.
  const stageNote = h("p", {class: "run-stage-note", role: "status"});
  const modeFacts = h("div", {class: "run-mode-facts"});
  const scopeLine = h("div", {class: "run-scope"});
  const collectionField = h("label", {class: "field run-field run-field-collection", for: "run-collection"},
    h("span", {}, "Collection"), collection);
  const capField = h("label", {class: "field run-field run-field-cap", for: "run-cap"},
    h("span", {}, "Chunk cap", tooltip("Chunks read per collection. Leave empty to read them all; a capped collection is reported as partially inspected, never as clean.")),
    maxChunks);
  const probeSection = h("fieldset", {class: "run-step run-probes"});
  const summary = h("p", {class: "run-summary", id: "run-summary"});
  const go = h("button", {class: "btn primary run-go-btn", type: "button",
                          "aria-describedby": "run-summary"}, icon("play"), "Run");
  const out = h("div", {class: "run-output"});
  const goDone = h("span", {class: "run-go-done"});
  let schema = null;
  let schemaError = null;

  const modeCards = RUN_MODES.map(m => {
    const input = h("input", {type: "radio", name: "run-mode", value: m.id, class: "run-mode-input",
                              id: `run-mode-${m.id}`, checked: m.id === mode});
    input.checked = m.id === mode;
    input.addEventListener("change", () => {
      if (!input.checked) return;
      mode = m.id;
      setParams({mode: mode === "audit" ? null : mode});
      draw();
    });
    return {mode: m, input, card: h("label", {class: "run-mode", for: `run-mode-${m.id}`, "data-mode": m.id},
      input,
      h("span", {class: "run-mode-head"},
        h("span", {class: "run-mode-glyph"}, icon(m.glyph)),
        h("span", {class: "run-mode-name"}, m.label),
        m.flag ? h("span", {class: "run-mode-flag"}, m.flag) : ""),
      h("span", {class: "run-mode-sum"}, m.summary),
      h("span", {class: "run-mode-cost"}, icon("clock"), m.cost))};
  });

  const singleStore = () => store.value && store.value !== "__all__";

  function drawStage(note) {
    stageNote.textContent = note;
  }

  function drawModeFacts() {
    const m = runModeOf(mode);
    modeFacts.replaceChildren(
      h("dl", {class: "run-facts"},
        h("div", {}, h("dt", {}, "Reads"), h("dd", {}, m.reads)),
        h("div", {}, h("dt", {}, "Writes"), h("dd", {}, m.writes)),
        h("div", {}, h("dt", {}, "Leaves you with"), h("dd", {}, m.produces))));
  }

  // What this run will and will not cover, stated before it starts rather
  // than discovered afterwards in a coverage field nobody opened.
  function drawScope() {
    if (!store.value) {
      scopeLine.replaceChildren(h("p", {class: "sub"}, "Choose a store to see what this run can reach."));
      return;
    }
    if (store.value === "__all__") {
      scopeLine.replaceChildren(statusLine(
        `Runs against all ${plural(state.stores.length, "registered store")}, one after another, in this tab. ` +
        "It is not a tracked run: leaving the page stops it after the current store.", "info"));
      return;
    }
    if (schemaError) {
      scopeLine.replaceChildren(statusLine(
        `The scope could not be previewed (${unavailableReason(schemaError)}). The run can still start; its coverage will say what it reached.`,
        "medium"));
      return;
    }
    if (!schema) {
      scopeLine.replaceChildren(h("p", {class: "sub"}, "Checking what this run can reach…"));
      return;
    }
    const all = schema.collections || [];
    const inScope = mode === "integrity"
      ? all.filter(c => c.name === collection.value)
      : mode === "posture" ? [] : all;
    const cap = mode === "posture" || mode === "integrity" ? 0 : Number(maxChunks.value) || 0;
    const capped = cap ? inScope.filter(c => Number(c.count || 0) > cap) : [];
    const unreadable = inScope.filter(c => c.error || c.enumerable === false);
    const chunks = inScope.reduce((n, c) => n + Number(c.count || 0), 0);
    const lines = [];
    if (mode === "posture") {
      lines.push(h("p", {class: "run-scope-k"}, icon("db"),
        h("span", {}, `${store.value}: configuration only; no collection is read.`)));
    } else if (mode === "integrity" && !collection.value) {
      lines.push(h("p", {class: "run-scope-k"}, icon("db"),
        h("span", {}, `${store.value}: choose one of its ${plural(all.length, "collection")}.`)));
    } else {
      lines.push(h("p", {class: "run-scope-k"}, icon("db"),
        h("span", {}, `${store.value}: ${plural(inScope.length, "collection")}, ${number(chunks)} chunks`,
          cap ? `, at most ${number(cap)} read from each` : ", every chunk read")));
      if (!capped.length && !unreadable.length) {
        lines.push(statusLine(inScope.length === 1 ? "The collection can be inspected in full."
                                                    : "Every collection in scope can be inspected in full.", "info"));
      }
    }
    if (capped.length) {
      lines.push(statusLine(
        `${plural(capped.length, "collection")} ${capped.length === 1 ? "holds" : "hold"} more chunks than the cap ` +
        `(${capped.map(c => c.name).join(", ")}). They will be inspected only in part, and their results will be inconclusive rather than clean.`,
        "medium"));
    }
    if (unreadable.length) {
      lines.push(statusLine(
        `${plural(unreadable.length, "collection")} cannot be enumerated by this connector (${unreadable.map(c => c.name).join(", ")}). ` +
        "Nothing inside them can be inspected; an absence of findings there proves nothing.", "medium"));
    }
    scopeLine.replaceChildren(...lines);
  }

  function drawCollections() {
    const names = (schema?.collections || []).map(c => [c.name, `${c.name} (${number(c.count || 0)} chunks)`]);
    const first = !singleStore() ? "Choose a store first"
      : schemaError ? "Collections unavailable" : names.length ? "Choose a collection" : "No collections found";
    collection.replaceChildren(...[["", first], ...names].map(([value, label]) =>
      h("option", {value, selected: value === wantedCollection}, label)));
    collection.value = names.some(([n]) => n === wantedCollection) ? wantedCollection : "";
  }

  async function loadScope() {
    schema = null;
    schemaError = null;
    drawCollections();
    drawScope();
    if (!singleStore()) return;
    const asked = store.value;
    try {
      const result = await loadStoreSchema(asked, 0, false);
      if (store.value !== asked) return;
      schema = result;
    } catch (e) {
      if (store.value !== asked) return;
      schemaError = e;
    }
    drawCollections();
    drawScope();
    drawSummary();
  }

  function drawProbes() {
    probeSection.hidden = mode !== "audit";
    probeSection.replaceChildren(
      h("legend", {class: "run-step-k"}, h("span", {class: "run-step-n"}, "3"), "Active checks",
        h("span", {class: "run-step-opt"}, "optional, off by default")),
      h("p", {class: "sub run-probes-lead"},
        "Both are off unless you switch them on for this run. They send traffic a passive audit does not. " +
        "A check that is on is recorded in the audit's scope and the audit log; one that is off is recorded as skipped, never as passed."),
      h("div", {class: "run-probe-grid"}, ACTIVE_PROBES.map(p => {
        const input = probeInputs[p.field];
        return h("label", {class: `run-probe check-row${input.checked ? " run-probe-on" : ""}`, for: p.id},
          input,
          h("span", {class: "run-probe-body"},
            h("span", {class: "run-probe-name"},
              h("span", {class: "strong"}, p.label), h("span", {class: "sub"}, ` — ${p.short}`)),
            h("span", {class: "run-probe-does"}, p.does),
            h("span", {class: "run-probe-effect"}, icon("alert"), p.effect),
            h("span", {class: "run-probe-state"}, input.checked ? "On for this run" : "Off: recorded as skipped")));
      })));
  }

  function drawSummary() {
    const m = runModeOf(mode);
    const target = !store.value ? "no store chosen yet"
      : store.value === "__all__" ? "every registered store, one after another" : store.value;
    const parts = [`${m.label} of ${target}`];
    if (singleStore() && mode === "integrity") {
      parts.push(collection.value ? `collection ${collection.value}` : "no collection chosen yet");
    }
    if (mode === "audit" || mode === "dpia") {
      parts.push(Number(maxChunks.value) ? `at most ${number(Number(maxChunks.value))} chunks per collection`
                                         : "every chunk");
    }
    if (mode === "audit") {
      const on = ACTIVE_PROBES.filter(p => probeInputs[p.field].checked).map(p => p.label);
      parts.push(on.length ? `active checks: ${on.join(", ")}` : "no active checks (recorded as skipped)");
    }
    summary.textContent = `${parts.join(" · ")}.`;
    const verb = {audit: "Run full audit", posture: "Run posture check",
                  integrity: "Run integrity scan", dpia: "Generate DPIA draft"}[mode];
    go.replaceChildren(icon("play"), verb);
  }

  function draw() {
    for (const {mode: m, input, card} of modeCards) {
      input.checked = m.id === mode;
      card.classList.toggle("run-mode-on", m.id === mode);
    }
    collectionField.hidden = mode !== "integrity";
    capField.hidden = !(mode === "audit" || mode === "dpia");
    go.className = "btn primary run-go-btn";
    drawModeFacts();
    drawProbes();
    drawScope();
    drawSummary();
  }

  // Every long action goes through the queue, so the console stays usable and
  // the run survives a reload.
  async function run(label, path, {body, runMode} = {}) {
    drawStage(`${label} submitted. This page tracks it; you can leave and come back.`);
    out.replaceChildren(loadingState(`Submitting ${label}`));
    let jobId;
    try {
      jobId = await startBackgroundRun(path, {body});
    } catch (e) {
      out.replaceChildren(panel(`${label} could not start`,
        errorState(e.status === 403 ? refusalText(e) : e.message)));
      drawStage("The run was not accepted. Resolve the error and try again.");
      return;
    }
    setParams({job: jobId, store: store.value, mode: runMode === "audit" ? null : runMode});
    await track(jobId, label, {focus: true});
  }

  // "All stores" has no single run to track: it fans out from this tab, so it
  // runs inline and says so rather than pretending to be a tracked run.
  async function runInline(label, work) {
    drawStage(`${label} is running across every registered store.`);
    out.replaceChildren(loadingState(`Running ${label}`));
    try {
      out.replaceChildren(await work());
      drawStage("Review each store's result and the coverage it achieved.");
      if (!box.isConnected) {
        runNotice(`${label} finished. Each store's audit is in History.`,
                  {label: "Open history", go: () => goTo("history")});
      }
    } catch (e) {
      out.replaceChildren(panel(`${label} failed`, errorState(e.message)));
      drawStage("The run failed. Its error is shown below the form.");
      if (!box.isConnected) runNotice(`${label} failed: ${e.message}`, {tone: "err"});
    }
  }

  async function track(jobId, label, {focus = false} = {}) {
    const job = await watchRun(jobId, out, {
      label, scope: store.value, kind: label,
      renderResult: (result, finished) => runResultView(finished, result, store.value),
    });
    const open = runOpenTarget(job);
    if (job.status === "succeeded") {
      drawStage("Review the results and the coverage this run actually achieved.");
      // The result is now the next thing to do, not another run. The way to
      // it also sits beside the Run button, where the reader's eyes are.
      go.className = "btn run-go-btn";
      // It is a plain button: the result card's own button is the one primary.
      goDone.replaceChildren(open && job.kind !== "pia"
        ? h("button", {class: "btn run-go-open", type: "button", onclick: open.go},
            icon("archive"), open.short)
        : "");
      if (focus) out.querySelector?.(".run-result-primary")?.focus?.();
    } else if (job.status === "interrupted") {
      drawStage("The run was interrupted and recorded nothing. Run it again.");
    } else if (job.status === "failed") {
      drawStage("The run failed. Its error is shown below the form.");
    }
    // Someone who left for another screen still hears how it ended, with the
    // way to the saved result.
    if (!box.isConnected && TERMINAL_RUN_STATES.has(String(job.status))) {
      const name = label || RUN_KIND_LABEL[job.kind] || "Run";
      const where = job.resource ? ` of ${job.resource}` : "";
      if (job.status === "succeeded") {
        runNotice(open?.saved ? `${name}${where} finished: ${open.saved}.` : `${name}${where} finished.`,
                  open ? {label: open.label, go: open.go} : {});
      } else {
        runNotice(`${name}${where} ${job.status === "failed" ? "failed" : "was interrupted"}.`,
                  {tone: "err", label: "Open Runs", go: () => goTo("jobs")});
      }
    }
  }

  function start() {
    if (!store.value) {
      out.replaceChildren(statusLine("Choose a store first.", "medium", {live: true}));
      store.focus?.();
      return;
    }
    const m = runModeOf(mode);
    const cap = Number(maxChunks.value) || 0;
    const id = encodeURIComponent(store.value);
    if (mode === "audit") {
      if (store.value === "__all__") {
        return runInline("Full audit (all stores)", () => auditAllStores(maxChunks.value, probes()));
      }
      const body = {include_integrity: true, ...probes()};
      if (cap) body.max_chunks_per_collection = cap;
      return run(m.label, `/stores/${id}/audit`, {body, runMode: mode});
    }
    if (mode === "posture") {
      if (store.value === "__all__") {
        return runInline("Posture (all stores)", () =>
          scopedStoreJob(store.value, "Posture", sid => `/stores/${encodeURIComponent(sid)}/posture`));
      }
      return run(m.label, `/stores/${id}/posture`, {runMode: mode});
    }
    if (mode === "integrity") {
      if (store.value === "__all__") {
        out.replaceChildren(statusLine("An integrity scan runs against one store and one collection.", "medium", {live: true}));
        return;
      }
      if (!collection.value) {
        out.replaceChildren(statusLine("Choose a collection for the integrity scan.", "medium", {live: true}));
        collection.focus?.();
        return;
      }
      return run(m.label, `/stores/${id}/scan/integrity?collection=${encodeURIComponent(collection.value)}`,
                 {runMode: mode});
    }
    if (store.value === "__all__") {
      return runInline("DPIA (all stores)", () => dpiaAllStores(cap));
    }
    return run(m.label, `/stores/${id}/pia`, {body: cap ? {max_chunks_per_collection: cap} : {}, runMode: mode});
  }
  go.addEventListener("click", start);

  store.addEventListener("change", async () => {
    setParams({store: store.value, job: null, collection: null});
    wantedCollection = "";
    out.replaceChildren();
    goDone.replaceChildren();
    drawStage(store.value ? "Check the scope, then run." : "Choose a store to scope this assessment.");
    draw();
    await loadScope();
  });
  collection.addEventListener("change", () => {
    wantedCollection = collection.value;
    setParams({collection: collection.value});
    drawScope();
    drawSummary();
  });
  maxChunks.addEventListener("change", () => {
    setParams({max: maxChunks.value});
    drawScope();
    drawSummary();
  });
  for (const input of Object.values(probeInputs)) {
    input.addEventListener("change", () => { drawProbes(); drawSummary(); });
  }

  const scoped = singleStore() ? store.value : "";
  box.append(pageHeader("assess", "Choose what to run and where. Every run is recorded with the coverage it actually achieved.",
    h("button", {class: "btn", type: "button", onclick: () => goTo("history", scoped ? {store: scoped} : {})},
      icon("archive"), scoped ? `Open history for ${scoped}` : "Open history")));
  box.append(panel(null, [
    h("fieldset", {class: "run-step"},
      h("legend", {class: "run-step-k"}, h("span", {class: "run-step-n"}, "1"), "What to run"),
      h("div", {class: "run-modes"}, modeCards.map(c => c.card)),
      modeFacts),
    h("fieldset", {class: "run-step"},
      h("legend", {class: "run-step-k"}, h("span", {class: "run-step-n"}, "2"), "Target"),
      h("div", {class: "run-target"},
        h("label", {class: "field run-field run-field-store", for: "run-store"}, h("span", {}, "Store"), store),
        collectionField,
        capField),
      scopeLine),
    probeSection,
    stageNote,
    h("div", {class: "run-go"}, summary, goDone, gated("operator", go))],
    null, {className: "run-form", label: "Run an assessment"}));
  box.append(out);

  draw();
  const watching = param("job");
  if (watching) {
    drawStage("Tracking a run started earlier.");
    track(watching, undefined);
  } else {
    drawStage(store.value ? "Check the scope, then run." : "Choose a store to scope this assessment.");
  }
  await loadScope();
  return box;
}

// What a finished run leads to. An audit and a scan are saved, so the card
// hands over to their page in History; a DPIA is not, so the draft itself
// is the result and is shown in full.
// Where a finished run's saved result lives, for the buttons and notices that
// lead to it. Only an audit or a scan that returned an id has a saved page.
function runOpenTarget(job) {
  const result = job?.result || {};
  const kind = String(job?.kind || "");
  const store = String(job?.resource || "").split("/")[0];
  if (job?.status !== "succeeded") return null;
  if (kind === "audit" && result.id) {
    return {label: "View audit results", short: "Open saved audit", saved: `audit saved as ${result.id}`,
            go: () => goTo("history", {audit: result.id, ...(store ? {store} : {})})};
  }
  if ((kind === "posture" || kind === "scan_integrity") && result.id) {
    return {label: "View scan results", short: "Open saved scan", saved: `recorded as ${result.id}`,
            go: () => goTo("history", {scan: result.id, ...(store ? {store} : {})})};
  }
  if (kind === "pia" && job.id) {
    return {label: "Open DPIA draft", short: "Open DPIA draft", saved: "the draft is ready",
            go: () => goTo("assess", {job: job.id, ...(store ? {store} : {}), mode: "dpia"})};
  }
  return null;
}

// A notice that outlives the screen that started the run: it stays until
// dismissed or opened, because it carries the only link to the result.
function runNotice(message, {label = "", go = null, tone = "ok"} = {}) {
  const node = h("div", {class: `toast run-notice run-notice-${tone}`, role: tone === "err" ? "alert" : "status"});
  const close = () => node.remove();
  node.append(
    h("span", {class: "run-notice-text"}, icon(tone === "err" ? "sev-critical" : "sev-ok"), message),
    h("span", {class: "run-notice-actions"},
      label && go ? h("button", {class: "btn small primary", type: "button",
                                 onclick: () => { close(); go(); }}, label) : "",
      h("button", {class: "btn small run-notice-close", type: "button", "aria-label": "Dismiss",
                   onclick: close}, icon("close"))));
  document.body.append(node);
  setTimeout(close, 30000);
  return node;
}

function runResultView(job, result, storeFallback = "") {
  const kind = String(job?.kind || "");
  const storeId = storeFallback && storeFallback !== "__all__"
    ? storeFallback : String(job?.resource || "").split("/")[0];
  if (kind === "audit") return auditCompletion({...result, store_id: result?.store_id || storeId});
  if (kind === "pia") return dpiaView(result || {}, {store: storeId, jobId: job?.id});
  if (kind === "posture" || kind === "scan_integrity") {
    return scanCompletion(result || {}, {store: storeId, label: kind === "posture" ? "Posture check" : "Integrity scan"});
  }
  return jobResult(result || {});
}

// Observed findings by severity, as a compact row of counts. Zero is said in
// words, next to the coverage it has to be read with.
function severityCounts(summary, {complete = false} = {}) {
  return severitySummary(summary, {variant: "inline", complete});
}

function coverageSentence(coverage) {
  const c = coverage || {};
  const complete = c.complete === true && c.status === "complete";
  const checks = c.checks_expected ? ` (${number(c.checks_complete || 0)} of ${plural(c.checks_expected, "check")} complete)` : "";
  return complete
    ? `Coverage: complete for the declared scope${checks}.`
    : `Coverage: ${c.status || "unknown"}${checks}. Where coverage is not complete, zero findings is inconclusive, not clean.`;
}

function auditCompletion(r) {
  const coverage = r.coverage || {};
  const complete = coverage.complete === true && coverage.status === "complete";
  const store = r.store_id || "";
  return h("div", {class: "run-result"},
    h("div", {class: "run-result-head"},
      h("div", {class: "run-result-text"},
        h("p", {class: "run-result-title"},
          r.id ? `Audit saved as ${r.id}` : "The audit finished but was not saved"),
        h("div", {class: "run-result-meta"},
          coverageChip(coverage.status),
          severityCounts(r.summary, {complete}))),
      r.id
        ? h("button", {class: "btn primary run-result-primary", type: "button",
                       onclick: () => goTo("history", {audit: r.id, ...(store ? {store} : {})})},
            icon("archive"), "View audit results")
        : ""),
    statusLine(coverageSentence(coverage), complete ? "info" : "medium"),
    r.id ? "" : statusLine("Without a saved audit, Criteria and Crypto keep reading the previous one.", "medium"),
    auditNextSteps(r));
}

function scanCompletion(result, {store = "", label = "Scan"} = {}) {
  const findings = result.findings || [];
  const coverage = resultCoverageOf(result);
  const complete = coverage.complete === true && coverage.status === "complete";
  const summary = {};
  for (const f of findings) summary[f.severity] = (summary[f.severity] || 0) + 1;
  return h("div", {class: "run-result"},
    h("div", {class: "run-result-head"},
      h("div", {class: "run-result-text"},
        h("p", {class: "run-result-title"},
          result.id ? `${label} recorded as ${result.id}` : `${label} finished`),
        h("div", {class: "run-result-meta"}, coverageChip(coverage.status),
          severityCounts(summary, {complete}))),
      result.id
        ? h("button", {class: "btn primary run-result-primary", type: "button",
                       onclick: () => goTo("history", {scan: result.id, ...(store ? {store} : {})})},
            icon("archive"), "View scan results")
        : ""),
    statusLine(coverageSentence(coverage), complete ? "info" : "medium"),
    store
      ? h("nav", {class: "next-steps", "aria-label": "Next steps"},
          h("span", {class: "next-steps-k"}, "Next"),
          h("button", {class: "btn", type: "button", onclick: () => goTo("findings", {store})},
            icon("alert"), "Findings for this store"),
          h("span", {class: "sub"}, "A scan is not a saved audit: Criteria and Crypto still read the latest full audit."))
      : "");
}

function resultCoverageOf(result) {
  return result?.coverage || (result?.stats || {}).coverage || {};
}
function jobResult(result) {
  return h("div", {},
    resultCoverage(result),
    panel("Findings", findingsTable(result.findings || [])),
    panel("Result data", h("details", {class: "evidence-data"},
      h("summary", {}, icon("code"), "Evidence data"), jsonBlock(result))));
}

// ----------------------------------------------------------- run tracking ---
// Long work is submitted to the queue and watched, rather than held open behind
// a blocking request. The job id goes in the URL, so a reload or a trip to
// another view does not lose the run.

const TERMINAL_RUN_STATES = new Set(["succeeded", "failed", "interrupted"]);
const RUN_POLL_MS = 1500;
const RUN_STATE = {
  queued: {tone: "info", text: "Queued"},
  running: {tone: "low", text: "Running"},
  succeeded: {tone: "ok", text: "Completed"},
  failed: {tone: "critical", text: "Failed"},
  interrupted: {tone: "medium", text: "Interrupted"},
};

async function startBackgroundRun(path, {method = "POST", body} = {}) {
  const opts = {method};
  if (body !== undefined) opts.body = JSON.stringify(body);
  const url = path.includes("?") ? `${path}&background=true` : `${path}?background=true`;
  const accepted = await api(url, opts);
  if (!accepted?.job_id) throw new Error("The server did not accept this as a background run.");
  return accepted.job_id;
}

function runElapsed(job) {
  const from = job.started_at || job.created_at;
  if (!from) return "-";
  const start = Date.parse(from);
  const end = job.finished_at ? Date.parse(job.finished_at) : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end)) return "-";
  const seconds = Math.max(0, Math.round((end - start) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function runNote(job) {
  const status = String(job.status || "queued");
  if (status === "failed") return errorState(job.error || "This run failed.");
  if (status === "interrupted") {
    return errorState(job.error ||
      "A restart ended this run before it finished. Its results were not recorded.");
  }
  if (status === "succeeded") return "";
  // There is no cancellation endpoint, so the card does not offer one.
  return statusLine(
    "This run continues on the server. You can navigate away and return to it; " +
    "it cannot be cancelled once started.", "info");
}

function currentPhaseId(progress) {
  const phases = progress && Array.isArray(progress.phases) ? progress.phases : [];
  const current = phases.find(phase => phase.state === "current");
  return current ? current.id : "";
}

function formatChunkCount(phase) {
  if (phase.state === "skipped" || phase.chunks_read == null) return "";
  const read = Number(phase.chunks_read).toLocaleString("en-US");
  if (phase.chunks_bound == null) return `${read} chunks read`;
  return `${read} of ${Number(phase.chunks_bound).toLocaleString("en-US")} chunks read`;
}

function runProgressList(job) {
  const phases = job.progress && Array.isArray(job.progress.phases) ? job.progress.phases : [];
  if (!phases.length) return "";
  const running = String(job.status) === "running";
  return h("ol", {class: "run-progress", "aria-label": "Assessment progress"},
    phases.map(phase => {
      const state = phase.state || "pending";
      const current = state === "current";
      const done = state === "done";
      const skipped = state === "skipped";
      const marker = done
        ? h("span", {class: "run-progress-mark", "aria-hidden": "true"})
        : current && running
          ? h("span", {class: "run-progress-bar", "aria-hidden": "true"},
              h("span", {class: "run-progress-bar-thumb"}))
          : current
            ? h("span", {class: "run-progress-bar is-stopped", "aria-hidden": "true"})
            : h("span", {class: "run-progress-pending", "aria-hidden": "true"});
      const sr = done ? "finished"
        : current ? (running ? "in progress" : "stopped")
        : skipped ? "skipped"
        : "not started";
      const chunks = formatChunkCount(phase);
      return h("li", {
        class: `run-progress-step is-${state}`,
        "aria-current": current ? "step" : null,
      },
        marker,
        h("div", {class: "run-progress-copy"},
          h("span", {class: "run-progress-label"}, phase.label || phase.id),
          h("span", {class: "sr-only"}, sr),
          phase.detail ? h("span", {class: "run-progress-detail"}, phase.detail) : "",
          chunks ? h("span", {class: "run-progress-chunks"}, chunks) : ""));
    }));
}

function runCard(job, {label, scope, body} = {}) {
  const status = String(job.status || "queued");
  const meta = RUN_STATE[status] || {tone: "unknown", text: status};
  return h("section", {class: `panel run-card run-${status}`},
    h("div", {class: "panel-title"},
      h("span", {}, label || RUN_KIND_LABEL[job.kind] || humanize(job.kind) || "Run"),
      stateChip(meta.tone, meta.text)),
    h("div", {class: "panel-body"},
      h("dl", {class: "kv"},
        h("dt", {}, "Scope"), h("dd", {class: "mono"}, scope || job.resource || "-"),
        h("dt", {}, "Job"), h("dd", {class: "mono"}, job.id || "-"),
        h("dt", {}, "Started"), h("dd", {},
          job.started_at || job.created_at
            ? formatWhen(job.started_at || job.created_at)
            : h("span", {class: "sub"}, "not yet")),
        h("dt", {}, "Elapsed"), h("dd", {}, runElapsed(job))),
      runProgressList(job),
      runNote(job),
      body || ""));
}

async function watchRun(jobId, container, opts = {}) {
  const {wait = ms => new Promise(done => setTimeout(done, ms)), attempts = 600} = opts;
  let job = {id: jobId, status: "queued", kind: opts.kind};
  let lastStatus = "";
  let lastPhaseId = "";
  container.replaceChildren(runCard(job, opts));
  for (let i = 0; i < attempts; i += 1) {
    try {
      job = await api(`/admin/jobs/${encodeURIComponent(jobId)}`);
    } catch (e) {
      container.replaceChildren(runCard({...job, status: "failed", error: e.message}, opts));
      return job;
    }
    const done = TERMINAL_RUN_STATES.has(String(job.status));
    let body = "";
    if (done && job.status === "succeeded" && opts.renderResult) {
      try { body = await opts.renderResult(job.result, job); }
      catch (e) { body = errorState(e.message); }
    }
    container.replaceChildren(runCard(job, {...opts, body}));
    const status = String(job.status || "queued");
    const phaseId = currentPhaseId(job.progress);
    if (status !== lastStatus || phaseId !== lastPhaseId) {
      const label = opts.label || job.kind || "Run";
      const phase = (job.progress && job.progress.phases || []).find(p => p.state === "current");
      if (done) {
        announce(`${label} ${RUN_STATE[status]?.text || status}`);
      } else if (phaseId && phaseId !== lastPhaseId && phase && phase.label) {
        announce(`${label}: ${phase.label}`);
      } else if (status !== lastStatus) {
        announce(`${label} ${RUN_STATE[status]?.text || status}`);
      }
      lastStatus = status;
      lastPhaseId = phaseId;
    }
    if (done) return job;
    await wait(RUN_POLL_MS);
  }
  return job;
}


// All stores, one after another, from this tab. Each store's audit is saved
// like any other, so the result is one row per store that leads to it, rather
// than every audit's full report stacked down the page.
async function auditAllStores(maxChunks, probes = {}) {
  if (!state.stores.length) return statusLine("No stores registered.", "medium");
  const rows = [];
  let failed = 0;
  for (const s of state.stores) {
    try {
      const body = {include_integrity: true, ...probes};
      if (maxChunks) body.max_chunks_per_collection = Number(maxChunks);
      const r = await api(`/stores/${encodeURIComponent(s.store_id)}/audit`, {method: "POST", body: JSON.stringify(body)});
      const coverage = r.coverage || {};
      rows.push(h("tr", {},
        h("td", {class: "mono"}, s.store_id),
        h("td", {}, executionChip(r.status)),
        h("td", {}, coverageChip(coverage.status)),
        h("td", {}, severityCounts(r.summary, {complete: coverage.complete === true && coverage.status === "complete"})),
        h("td", {}, r.id
          ? h("button", {class: "btn small", type: "button",
                         "aria-label": `Open audit ${r.id} for ${s.store_id}`,
                         onclick: () => goTo("history", {audit: r.id, store: s.store_id})},
              icon("archive"), "Open audit")
          : h("span", {class: "sub"}, "not saved"))));
    } catch (e) {
      failed += 1;
      rows.push(h("tr", {},
        h("td", {class: "mono"}, s.store_id),
        h("td", {}, stateChip("critical", "error")),
        h("td", {}, coverageChip("unknown")),
        h("td", {class: "sub"}, e.message),
        h("td", {}, "")));
    }
  }
  return panel("Full audit, all stores", h("div", {},
    statusLine(`${state.stores.length - failed} of ${plural(state.stores.length, "store")} returned an audit. ` +
               "Read each row's coverage before its findings.", failed ? "medium" : "info"),
    table(["Store", "Result", "Coverage", "Observed findings", {sr: "Open"}], rows)));
}

// DPIA drafts for every store. They are not saved anywhere but this page, so
// each is shown in a fold, one per store, with its headline states in the row.
async function dpiaAllStores(cap = 0) {
  if (!state.stores.length) return statusLine("No stores registered.", "medium");
  const items = [];
  for (const s of state.stores) {
    try {
      const r = await api(`/stores/${encodeURIComponent(s.store_id)}/pia`,
        {method: "POST", body: JSON.stringify(cap ? {max_chunks_per_collection: cap} : {})});
      items.push(h("details", {class: "dpia-fold"},
        h("summary", {}, h("span", {class: "mono"}, s.store_id), dpiaHeadline(r)),
        dpiaView(r, {store: s.store_id})));
    } catch (e) {
      items.push(h("div", {class: "dpia-fold dpia-fold-error"},
        h("span", {class: "mono"}, s.store_id), statusLine(`No draft: ${e.message}`, "error")));
    }
  }
  return panel("DPIA drafts, all stores", h("div", {},
    statusLine("Drafts built from this pass are not saved. Download each one you need before leaving the page.", "medium"),
    items));
}

// ------------------------------------------------------------------ DPIA ---
// A DPIA draft is a document, not a list of findings. It used to render
// through the generic result view, which found no `findings` in it and said
// "No findings" above a folded JSON dump that held the actual risks and
// safeguards. It now reads as the four Article 35(7) parts, with what it does
// not establish stated first.
const DPIA_SAFEGUARD = {
  "GAP": {tone: "critical", text: "gap"},
  "in place / no gap detected": {tone: "ok", text: "no gap detected"},
  "not assessed — review required": {tone: "unknown", text: "not assessed"},
  "partially assessed — review required": {tone: "medium", text: "partly assessed"},
};
const DPIA_RESIDUAL = {high: "critical", medium: "medium", low: "ok", unknown: "unknown"};

function dpiaHeadline(p) {
  return h("span", {class: "dpia-headline"},
    p.high_risk ? stateChip("critical", "High-risk indicators observed") : stateChip("info", "standard risk"),
    stateChip(DPIA_RESIDUAL[p.residual_risk] || "unknown", `residual risk ${p.residual_risk || "unknown"}`),
    p.assessment_complete ? stateChip("ok", "every safeguard measured")
                          : stateChip("medium", "incomplete: review required"),
    controllerActionRequired(p) ? stateChip("high", "Controller decision needed · DPO advises") : "");
}

// Under GDPR Art. 35(2) the controller carries out the DPIA and the DPO
// advises. The server says so in `controller_action_required`; older drafts
// only carried `dpo_action_required`, which meant the same thing.
function controllerActionRequired(p) {
  return Boolean(p.controller_action_required ?? p.dpo_action_required);
}

function dpiaView(p, {store = "", jobId = ""} = {}) {
  const risks = p.risks || [];
  const safeguards = p.safeguards || [];
  const unassessed = p.unassessed_safeguards || [];
  const categories = p.data_categories || [];
  const coverage = p.coverage || {};
  const slug = String(store || p.store || "store").replace(/[^a-zA-Z0-9_-]/g, "_");
  return h("div", {class: "dpia-view"},
    h("div", {class: "dpia-top"},
      dpiaHeadline(p),
      h("div", {class: "dpia-actions"},
        store && jobId
          ? h("button", {class: "btn primary run-result-primary", type: "button",
                         onclick: () => downloadDpiaDocument(store, jobId)}, icon("file"), "Download DPIA document")
          : "",
        h("button", {class: "btn", type: "button",
                     onclick: () => downloadText(JSON.stringify(p, null, 2), `vecshield-dpia-${slug}.json`,
                                                 "application/json", `DPIA draft — ${store || p.store || ""}`)},
          icon("code"), "Download as JSON"))),
    statusLine("A draft built from what this run observed, in the shape of GDPR Article 35(7). " +
               "It is not a legal determination. The controller completes and owns it; your DPO advises.", "info"),
    p.high_risk_basis ? statusLine(String(p.high_risk_basis), "info") : "",
    p.roles_note ? h("p", {class: "sub"}, String(p.roles_note)) : "",
    p.assessment_complete
      ? statusLine("Every safeguard below was measured over its full scope.", "ok")
      : statusLine(`Incomplete (coverage: ${coverage.status || "unknown"}). This draft does not establish ` +
                   `${unassessed.length ? unassessed.join(", ") : "every safeguard"}. An unmeasured safeguard is not a ` +
                   "safeguard in place: each row marked for review needs a documented decision.", "medium"),
    h("div", {class: "dpia-grid"},
      h("section", {class: "dpia-part"},
        h("h3", {}, h("span", {class: "dpia-part-k"}, "(a)"), "The processing"),
        h("p", {}, p.processing_description || "-"),
        h("p", {class: "dpia-sub-k"}, "Categories of personal data observed"),
        categories.length
          ? h("ul", {class: "dpia-list"}, categories.map(c => h("li", {}, c)))
          : h("p", {class: "sub"}, p.assessment_complete ? "None detected in the inspected scope."
            : "None observed, but classification did not cover the whole scope: this is not evidence of absence.")),
      h("section", {class: "dpia-part"},
        h("h3", {}, h("span", {class: "dpia-part-k"}, "(b)"), "Necessity and proportionality"),
        h("p", {}, p.necessity || "-"))),
    h("section", {class: "dpia-part"},
      h("h3", {}, h("span", {class: "dpia-part-k"}, "(c)"), `Risks to data subjects (${number(risks.length)})`),
      risks.length
        ? table(["Severity", "Risk", "Where", "Impact on rights"], risks.map(r => h("tr", {},
            h("td", {}, badge(r.severity)),
            h("td", {}, h("div", {}, r.title || "-"), h("div", {class: "sub mono"}, r.category || "")),
            h("td", {}, r.collection || h("span", {class: "sub"}, "store")),
            h("td", {}, r.to_rights || "-"))))
        : h("p", {class: "sub"}, "No high or critical finding was observed. Read this with the coverage above.")),
    h("section", {class: "dpia-part"},
      h("h3", {}, h("span", {class: "dpia-part-k"}, "(d)"), "Safeguards and measures"),
      table(["Control", "Status", "Assessed by", "Open findings", "Basis or remediation"],
        safeguards.map(s => {
          const meta = DPIA_SAFEGUARD[s.status] || {tone: "unknown", text: s.status || "unknown"};
          return h("tr", {},
            h("td", {}, s.control),
            h("td", {}, stateChip(meta.tone, meta.text, {title: s.status || ""})),
            h("td", {class: "mono"}, s.assessed_by || "-"),
            h("td", {}, number(s.open_findings || 0)),
            h("td", {}, s.remediation || s.reason || h("span", {class: "sub"}, "-")));
        }))),
    controllerActionRequired(p)
      ? statusLine("A controller decision, with the DPO's advice, is needed before this processing continues" +
                   (unassessed.length ? `, including a documented decision on: ${unassessed.join(", ")}.` : "."), "high")
      : "",
    store && !jobId
      ? h("p", {class: "sub"}, "This draft was produced inline and is kept only on this page; download it to keep it.")
      : "",
    h("details", {class: "evidence-data"}, h("summary", {}, icon("code"), "Draft data"), jsonBlock(p)));
}

// The printable document for the draft on screen, rendered by the server from
// the finished run, so it cannot differ from what was read.
async function downloadDpiaDocument(storeId, jobId) {
  try {
    const html = await api(`/stores/${encodeURIComponent(storeId)}/pia/html?job_id=${encodeURIComponent(jobId)}`);
    downloadText(html, `vecshield-dpia-${String(storeId).replace(/[^a-zA-Z0-9_-]/g, "_")}.html`,
                 "text/html", `DPIA — ${storeId}`);
  } catch (e) { toast(unavailableReason(e), "err"); }
}

function resultCoverage(result) {
  const coverage = result.coverage || (result.stats || {}).coverage || {};
  const outcomes = result.check_outcomes || (result.stats || {}).check_outcomes || [];
  const complete = coverage.complete === true && coverage.status === "complete";
  return panel("Assessment coverage", h("div", {},
    statusLine(`Coverage: ${coverage.status || "unknown"}. ${complete ? "Complete for the declared assessment scope." : "Assessment is incomplete or coverage is unknown; zero findings is inconclusive."}`, complete ? "info" : "medium"),
    outcomes.length ? coverageChart(coverage, {label: "Checks inspected in this run"}) : "",
    coverage.reason ? h("p", {}, coverage.reason) : "",
    outcomes.length ? table(["Check", "Collection", "Outcome", "Coverage", "Reason"], outcomes.map(c => h("tr", {},
      h("td", {}, c.check ? [h("div", {}, checkLabel(c.check)), h("div", {class: "sub mono"}, c.check)] : "-"),
      h("td", {}, c.collection || "Store scope"),
      h("td", {}, outcomeChip(c.outcome),
        (c.coverage || {}).crypto_state ? h("div", {}, recordChip(c)) : null),
      h("td", {}, coverageChip((c.coverage || {}).status)), h("td", {}, c.reason || "-"))))
      : statusLine("No structured check outcomes are recorded for this result.", "medium")));
}

// A run's declared scope, and the part of it a check actually reached. The
// difference between the two is what the heatmap hatches: a collection nobody
// inspected must not render as a clean row.
function auditScope(result) {
  const outcomes = result.check_outcomes || (result.stats || {}).check_outcomes || [];
  const declared = (result.scope || {}).collections;
  if (!outcomes.length) return {inspected: null, scope: null};
  const inspected = new Set();
  for (const outcome of outcomes) {
    if (outcome.collection && ["passed", "failed", "inconclusive"].includes(outcome.outcome)) {
      inspected.add(outcome.collection);
    }
  }
  return {
    inspected: [...inspected],
    scope: Array.isArray(declared) ? declared : null,
  };
}

function auditSummary(r) {
  const findings = (r.jobs || []).flatMap(j => j.findings || []);
  return h("div", {},
    h("div", {class: "bar"}, h("span", {class: "mono"}, `Audit ID: ${r.id || "unrecorded"}`), executionChip(r.status),
      r.id && r.store_id ? h("button", {class: "btn", onclick: () => downloadAuditReport(r.store_id, r.id)}, icon("file"), "Download saved report") : ""),
    resultCoverage(r),
    severitySummary(r.summary, {columns: true, sub: "Observed findings in this audit, by severity."}),
    panel("Findings by collection and severity", heatmapChart(findings, auditScope(r))),
    (r.errors || []).length ? panel("Store errors", table(["Store", "Error"], r.errors.map(e => h("tr", {}, h("td", {class: "mono"}, e.store), h("td", {}, e.error))))) : "",
    panel("Policy violations", table(["Severity", "Policy", "Action", "Collection"], (r.violations || []).map(v => h("tr", {}, h("td", {}, badge(v.severity)),
      h("td", {}, h("div", {class: "mono"}, v.policy_id),
        CRYPTO_POLICIES[v.policy_id] ? h("div", {class: "sub"}, `Crypto posture: ${CRYPTO_POLICIES[v.policy_id].when.toLowerCase()}`) : ""),
      h("td", {class: "mono"}, v.action), h("td", {}, v.collection || "-"))))),
    panel("Findings", findingsTable(findings)),
    auditNextSteps(r));
}

// Where a result leads. An audit is read in four places after it lands: its
// findings, its crypto posture, the criteria it informs, and the release gate.
function auditNextSteps(r) {
  const store = r.store_id || "";
  if (!store) return "";
  const audit = r.id ? {audit: r.id} : {};
  const step = (label, glyph, view, params) => h("button", {class: "btn", type: "button",
    onclick: () => goTo(view, params)}, icon(glyph), label);
  return h("nav", {class: "next-steps", "aria-label": "Next steps"},
    h("span", {class: "next-steps-k"}, "Next"),
    step("Findings for this store", "alert", "findings", {store}),
    step("Crypto posture", "lock", "crypto", {store, ...audit}),
    step("Criteria", "check", "criteria", {store, ...audit}),
    step("Release gate", "shield", "crypto", {store, ...audit, section: "gate"}),
    r.id ? "" : h("span", {class: "sub"}, "This result was not saved; the steps read the latest saved audit."));
}


async function scopedStoreJob(store, label, pathForStore, method = "POST") {
  if (!store) return statusLine("Choose a store first.", "medium");
  if (store !== "__all__") return simpleJob(pathForStore(store), method);
  if (!state.stores.length) return statusLine("No stores registered.", "medium");
  const rows = [];
  const findings = [];
  const payloads = [];
  for (const s of state.stores) {
    try {
      const r = await api(pathForStore(s.store_id), {method});
      payloads.push({store: s.store_id, result: r});
      rows.push(h("tr", {}, h("td", {class: "mono"}, s.store_id), h("td", {}, badge(r.max_severity || "info")), h("td", {}, number((r.findings || []).length)), h("td", {}, coverageChip((r.coverage || (r.stats || {}).coverage || {}).status))));
      findings.push(...((r.findings || []).map(f => ({...f, store: f.store || s.store_id}))));
    } catch (e) {
      rows.push(h("tr", {}, h("td", {class: "mono"}, s.store_id), h("td", {}, "-"), h("td", {}, "Unknown"), h("td", {}, stateChip("critical", "error"), h("div", {class: "sub"}, e.message))));
    }
  }
  return h("div", {},
    panel(`${label} results`, table(["Store", "Severity", "Observed findings", "Coverage / error"], rows)),
    findings.length ? panel("Findings", findingsTable(findings)) : "",
    panel("Result data", h("details", {class: "evidence-data"}, h("summary", {}, icon("code"), "Evidence data"), jsonBlock(payloads))));
}

async function simpleJob(path, method = "GET") {
  const r = await api(path, {method});
  const findings = [
    ...(r.findings || []),
    ...((r.jobs || []).flatMap(j => j.findings || [])),
  ];
  return panel("Result", h("div", {},
    resultCoverage(r),
    findings.length ? findingsTable(findings) : "",
    h("details", {class: "evidence-data", open: !findings.length},
      h("summary", {}, icon("code"), "Evidence data"),
      jsonBlock(r))));
}

// ---------------------------------------------------------------- History ---
// One switch for everything History holds: its two lists and the Runs view
// within it. It replaced a chrome switch (History | Runs) stacked above an
// in-page one (Saved audits | Individual scans), two rows that both looked
// like "where am I". `active` is "audits", "scans" or "runs". On History,
// `onList` swaps the lists in place; anything that changes screen navigates,
// so the switch on Runs (which has no `onList`) only navigates. The scan count
// is shown only when it is known; on Runs it is not fetched, so it is absent
// rather than a guessed number.
function historySwitch(active, {scanCount = null, onList = null} = {}) {
  const options = [["audits", "Saved audits"],
                   ["scans", scanCount == null ? "Individual scans" : `Individual scans (${number(scanCount)})`],
                   ["runs", views.jobs[0]]];
  const inPlace = Boolean(onList) && active !== "runs";
  return segmented({label: "History views", className: "archive-switch", options, value: active,
                    dataKey: "list", navigates: !inPlace,
                    controls: inPlace ? id => (id === "runs" ? null : `archive-${id}`) : null,
                    onPick: id => {
                      if (id === "runs") goTo("jobs", carriedParams("jobs"));
                      else if (inPlace) onList(id);
                      else goTo("history", {...carriedParams("history"), ...(id === "scans" ? {list: "scans"} : {})});
                    }});
}

// Two lists, one at a time: saved audits (the default, and what every other
// screen reads) and the individual scans behind them. Both are fetched, so a
// failure in either is visible whichever list is showing.
async function scanArchivePanel(storeValue = "") {
  const params = new URLSearchParams({limit: "500"});
  // Saved audits are filed by registry id, so they can be scoped to the store.
  // Jobs carry the connector's own name for the store, so they are fetched
  // whole and filtered in the table below rather than risk an empty match.
  const [audits, jobs] = await Promise.allSettled([savedAuditsPanel(storeValue), api(`/admin/history?${params}`).then(requireHistory)]);
  const list = param("list") === "scans" ? "scans" : "audits";
  const auditsBody = audits.status === "fulfilled" ? audits.value
    : panel("Saved audits unavailable", statusLine(unavailableReason(audits.reason), "medium"));
  const jobCount = jobs.status === "fulfilled" ? (jobs.value.jobs || []).length : null;
  const scansBody = jobs.status === "fulfilled"
    ? h("div", {class: "archive-list"},
        statusLine("Up to 500 recent scans. A scan inside an audit keeps its parent audit's ID; legacy jobs have no known parent. Matching timestamps do not imply a shared audit."),
        archiveTable(jobs.value.jobs || []))
    : panel("Scan history unavailable", statusLine(unavailableReason(jobs.reason), "medium"));
  const panes = {audits: h("div", {id: "archive-audits"}, auditsBody),
                 scans: h("div", {id: "archive-scans"}, scansBody)};
  const switcher = historySwitch(list, {scanCount: jobCount, onList: id => {
    setParams({list: id === "scans" ? "scans" : null});
    for (const [key, pane] of Object.entries(panes)) pane.hidden = key !== id;
  }});
  for (const [key, pane] of Object.entries(panes)) pane.hidden = key !== list;
  return h("div", {class: "archive-body"}, switcher, panes.audits, panes.scans);
}

const ARCHIVE_WHEN = [["", "Any time"], ["1", "Last 24 hours"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"]];
const ARCHIVE_SORT = [["new", "Newest first"], ["old", "Oldest first"], ["severe", "Most severe first"],
                      ["findings", "Most findings first"]];

function auditFindingTotal(a) {
  return severityOrder.reduce((n, s) => n + Number((a.summary || {})[s] || 0), 0);
}

// Saved audits as a dense, filterable table. The store filter is asked of the
// server; the rest filter what has been loaded, and the count says so.
async function savedAuditsPanel(storeValue = "") {
  const rows = [];
  let offset = 0;
  let hasMore = false;
  let loadError = "";
  const scoped = storeValue && storeValue !== "__all__" ? storeValue : "";
  const search = textInput(param("aq"), {placeholder: "Audit ID", "aria-label": "Search audit IDs", type: "search"});
  const storeFilter = selectInput([["", "All stores"], ...(state.stores || []).map(s => [s.store_id, s.store_id]),
                                   ...(scoped && !(state.stores || []).some(s => s.store_id === scoped) ? [[scoped, scoped]] : [])],
                                  scoped, {"aria-label": "Store"});
  const coverageFilter = selectInput([["", "Any coverage"], ["complete", "Complete"], ["partial", "Partial"], ["unknown", "Unknown"]],
                                     param("coverage"), {"aria-label": "Coverage"});
  const sevFilter = selectInput([["", "Any severity"], ...severityOrder.map(s => [s, `${s} or worse`])],
                                param("severity"), {"aria-label": "Worst finding at least"});
  const whenFilter = selectInput(ARCHIVE_WHEN, param("when"), {"aria-label": "Started"});
  const sort = selectInput(ARCHIVE_SORT, param("sort") || "new", {"aria-label": "Sort"});
  const count = h("span", {class: "result-count"}, "");
  const message = h("div", {});
  const auditTable = dataTable(["Started", "Store", "Coverage", "Observed findings", "Audit ID", {sr: "Open"}],
                               {wrapClass: "table-wrap archive-table"});
  const more = h("button", {class: "btn small", type: "button", onclick: load}, "Load more audits");

  function visible() {
    const days = Number(whenFilter.value) || 0;
    const since = days ? Date.now() - days * 86400000 : 0;
    const q = String(search.value || "").trim().toLowerCase();
    const list = rows.filter(a => {
      if (q && !String(a.id || "").toLowerCase().includes(q)) return false;
      const cov = String((a.coverage || {}).status || "unknown");
      if (coverageFilter.value && (coverageFilter.value === "unknown"
            ? ["complete", "partial"].includes(cov) : cov !== coverageFilter.value)) return false;
      if (sevFilter.value && !severityMeets(a.max_severity, sevFilter.value)) return false;
      if (since && !(toMillis(a.started_at) >= since)) return false;
      return true;
    });
    const rank = a => severityOrder.length - Math.max(0, severityOrder.indexOf(String(a.max_severity || "info")));
    const byTime = (a, b) => String(b.started_at || "").localeCompare(String(a.started_at || ""));
    const order = {
      new: byTime,
      old: (a, b) => -byTime(a, b),
      severe: (a, b) => rank(b) - rank(a) || auditFindingTotal(b) - auditFindingTotal(a) || byTime(a, b),
      findings: (a, b) => auditFindingTotal(b) - auditFindingTotal(a) || byTime(a, b),
    }[sort.value] || byTime;
    return list.sort(order);
  }

  function draw() {
    const list = visible();
    count.textContent = `${number(list.length)} of ${number(rows.length)} loaded` + (hasMore ? " · more to load" : "");
    auditTable.setRows(list.map(a => {
      const cov = a.coverage || {};
      const complete = cov.complete === true && cov.status === "complete";
      const open = () => goTo("history", {audit: a.id, ...(scoped ? {store: scoped} : {})});
      return h("tr", {class: "archive-row"},
        h("td", {}, formatWhen(a.started_at)),
        h("td", {class: "mono"}, a.store_id || a.store || "-"),
        h("td", {}, h("span", {class: "archive-cov"}, coverageChip(cov.status),
          cov.checks_expected ? h("span", {class: "sub"}, `${number(cov.checks_complete || 0)}/${number(cov.checks_expected)} checks`) : "")),
        h("td", {}, severityCounts(a.summary, {complete})),
        h("td", {class: "mono archive-id"}, a.id),
        h("td", {}, h("button", {class: "btn small", type: "button", onclick: open,
                                 "aria-label": `Open audit ${a.id}`}, "Open")));
    }), {empty: rows.length ? "No loaded audit matches these filters." : "No saved audits yet."});
  }

  async function load() {
    more.disabled = true;
    const params = new URLSearchParams({limit: "50", offset: String(offset)});
    if (scoped) params.set("store_id", scoped);
    try {
      const result = requireHistory(await api(`/admin/history/audits?${params}`));
      rows.push(...(result.audits || []));
      offset = result.next_offset ?? rows.length;
      hasMore = Boolean(result.has_more);
      more.hidden = !hasMore;
      loadError = "";
      if (rows.length) message.replaceChildren();
      else message.replaceChildren(statusLine("No saved audit snapshots. Run a full audit to create one."));
    } catch (e) {
      loadError = unavailableReason(e);
      message.replaceChildren(statusLine(`Saved audits unavailable: ${loadError}`, "medium"));
    } finally { more.disabled = false; }
    draw();
  }

  const filters = {aq: search, coverage: coverageFilter, severity: sevFilter, when: whenFilter,
                   sort};
  for (const [name, input] of Object.entries(filters)) {
    input.addEventListener(input.tagName === "SELECT" ? "change" : "input", () => {
      setParams({[name]: name === "sort" && input.value === "new" ? null : input.value});
      draw();
    });
  }
  // The store is filtered by the server, so changing it reloads the list.
  storeFilter.addEventListener("change", () => goTo("history", {store: storeFilter.value}));

  await load();
  return h("div", {class: "archive-list"},
    toolbar("Filter saved audits", [
      h("div", {class: "search-field"}, icon("search"), search),
      storeFilter, coverageFilter, sevFilter, whenFilter, sort, count], {className: "archive-filters"}),
    message,
    auditTable.node,
    h("div", {class: "archive-more"}, more));
}

// Saved audits open as their own page in History (`#/history?audit=<id>`),
// not a dialog: a link to one can be shared, and Back returns to the list.
function showHistoryAudit(id) {
  goTo("history", {audit: id});
}

const AUDIT_TABS = [["summary", "Summary"], ["coverage", "Coverage"], ["findings", "Findings"],
                    ["violations", "Policy violations"], ["data", "Snapshot data"]];

async function savedAuditView(id) {
  const box = h("div", {class: "archive-view archive-detail"});
  const store = param("store");
  box.append(pageHeader(recordTitle("Audit", id),
    "One saved audit: what it covered, what it observed, and where to act on it.", null,
    {back: {label: "All saved audits", className: "archive-back", onclick: () => climbOut("history")}}));
  let audit;
  try {
    audit = await api(`/admin/history/audits/${encodeURIComponent(id)}`);
  } catch (e) {
    box.append(panel(`Audit ${id}`, errorState(unavailableReason(e), () => route())));
    return box;
  }
  const coverage = audit.coverage || {};
  const complete = coverage.complete === true && coverage.status === "complete";
  const findings = (audit.jobs || []).flatMap(j => j.findings || []);
  const violations = audit.violations || [];
  const outcomes = audit.check_outcomes || [];
  const storeId = audit.store_id || store || "";
  const started = toMillis(audit.started_at);
  const finished = toMillis(audit.finished_at);
  const took = Number.isFinite(started) && Number.isFinite(finished)
    ? Math.max(0, Math.round((finished - started) / 1000)) : null;

  box.append(recordHead({
    meta: [
      h("span", {class: "mono"}, storeId || "-"),
      formatWhen(audit.started_at),
      took == null ? "" : h("span", {class: "sub"}, took < 60 ? `took ${took}s` : `took ${Math.floor(took / 60)}m ${took % 60}s`),
      coverageChip(coverage.status),
      severityCounts(audit.summary, {complete})],
    action: storeId && audit.id
      ? h("button", {class: "btn", type: "button", onclick: () => downloadAuditReport(storeId, audit.id)},
          icon("file"), "Download saved report")
      : "",
    notes: [
      statusLine(coverageSentence(coverage), complete ? "info" : "medium"),
      audit.coverage_as_recorded || audit.reconstructed_jobs
        ? statusLine("This audit predates structured coverage; some outcomes were reconstructed and are marked inconclusive.", "medium")
        : ""],
    nextSteps: auditNextSteps({...audit, store_id: storeId}),
  }));

  const counts = {coverage: outcomes.length, findings: findings.length, violations: violations.length};
  let tab = AUDIT_TABS.some(([t]) => t === param("tab")) ? param("tab") : "summary";
  // The sections are tabs over one panel. Every tab stays in the Tab order
  // (the page pattern), and the open one travels in the link as tab=.
  const body = h("div", {class: "archive-tab-body"});
  const tabs = tabList({
    id: "audit", label: "Audit sections", className: "tabs archive-tabs", panel: body, panelId: "audit-tabpanel",
    current: tab, dataKey: "tab",
    tabs: AUDIT_TABS.map(([t, label]) => [t, counts[t] == null ? label
      : [label, " ", h("span", {class: "tab-count"}, number(counts[t]))]]),
    onSelect: t => { tab = t; setParams({tab: t === "summary" ? null : t}); drawTab(); },
  });
  const tabBar = tabs.bar;

  function drawTab() {
    tabs.select(tab);
    if (tab === "coverage") body.replaceChildren(resultCoverage(audit));
    else if (tab === "findings") body.replaceChildren(panel(`Findings (${number(findings.length)})`, findingsTable(findings)));
    else if (tab === "violations") {
      body.replaceChildren(panel(`Policy violations (${number(violations.length)})`,
        table(["Severity", "Policy", "Action", "Collection"], violations.map(v => h("tr", {},
          h("td", {}, badge(v.severity)),
          h("td", {}, h("div", {class: "mono"}, v.policy_id),
            CRYPTO_POLICIES[v.policy_id] ? h("div", {class: "sub"}, `Crypto posture: ${CRYPTO_POLICIES[v.policy_id].when.toLowerCase()}`) : ""),
          h("td", {class: "mono"}, v.action), h("td", {}, v.collection || "-"))))));
    } else if (tab === "data") {
      body.replaceChildren(panel("Snapshot data", h("details", {class: "evidence-data", open: true},
        h("summary", {}, icon("code"), "The saved snapshot, as recorded"), jsonBlock(audit))));
    } else {
      body.replaceChildren(
        severitySummary(audit.summary, {columns: true, className: "archive-kpis",
                                        sub: "Observed findings in this audit, by severity."}),
        h("div", {class: "archive-summary-grid"},
          panel("Findings by collection and severity", h("div", {class: "archive-heatmap"}, heatmapChart(findings, auditScope(audit)))),
          panel("Checks", h("div", {},
            outcomes.length ? coverageChart(coverage, {label: "Checks inspected in this run"}) : "",
            statusLine(outcomes.length
              ? `${plural(outcomes.length, "check outcome")} recorded. The Coverage tab lists each one with its reason.`
              : "No structured check outcomes are recorded for this audit.", outcomes.length ? "info" : "medium"),
            h("button", {class: "btn small", type: "button",
                         onclick: () => {
                           tab = "coverage";
                           setParams({tab});
                           drawTab();
                           tabs.buttons[AUDIT_TABS.findIndex(([t]) => t === "coverage")]?.focus?.();
                         }}, "Open the coverage table")))),
        (audit.errors || []).length
          ? panel("Store errors", table(["Store", "Error"], audit.errors.map(e => h("tr", {}, h("td", {class: "mono"}, e.store), h("td", {}, e.error)))))
          : "");
    }
  }
  drawTab();
  box.append(tabBar, body);
  return box;
}

async function downloadAuditReport(storeId, auditId) {
  try {
    const html = await api(`/stores/${encodeURIComponent(storeId)}/report?audit_id=${encodeURIComponent(auditId)}`);
    downloadText(html, `vecshield-audit-${String(auditId).replace(/[^a-zA-Z0-9_-]/g, "_")}.html`,
                 "text/html", `Report — ${auditId}`);
  } catch (e) { toast(unavailableReason(e), "err"); }
}

// A download can fail for reasons the page cannot control: no Blob URL support,
// a blocked download, a sandboxed frame. Failing silently would leave someone
// waiting for a file that is never coming, so the content is shown instead.
function downloadText(text, filename, type, title) {
  let url = null;
  try {
    url = URL.createObjectURL(new Blob([text], {type}));
    const link = h("a", {href: url, download: filename});
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`${filename} downloaded.`);
    return true;
  } catch (e) {
    if (url) { try { URL.revokeObjectURL(url); } catch { /* already gone */ } }
    modal(title || filename, h("div", {},
      statusLine("This browser would not start the download " +
                 `(${e.message}). The content is below; copy or save it by hand.`,
                 "medium"),
      h("div", {class: "bar"},
        h("button", {class: "btn small", type: "button",
                     onclick: () => copyText(text, filename)}, icon("copy"), "Copy")),
      h("pre", {}, text)), null, "Close", {stack: true});
    return false;
  }
}

function archiveTable(jobs) {
  const data = archiveRows(jobs || []);
  const search = textInput(param("q"), {placeholder: "Search scans", "aria-label": "Search individual scans", type: "search"});
  const kind = selectInput([["", "All kinds"], ...uniqueValues(data, j => j.kind).map(x => [x, x])], param("kind"), {ariaLabel: "Kind"});
  const store = selectInput([["", "All stores"], ...uniqueValues(data, j => j.store).map(x => [x, storeLabel(x)])], param("scanstore"), {ariaLabel: "Store"});
  const sev = selectInput([["", "Any severity"], ...severityOrder.map(s => [s, `${s} or worse`])], param("severity"), {ariaLabel: "Minimum severity"});
  const withFindings = h("input", {type: "checkbox", "aria-label": "Only scans with findings"});
  const count = h("span", {class: "result-count"}, "");
  const scanTable = dataTable(["Created", "Scan ID", "Store", "Kind", "Severity", "Findings", "Coverage", {sr: "Open"}],
                              {wrapClass: "table-wrap archive-table"});

  function jobText(j) {
    return [j.id, j.audit_id, j.store, j.kind, j.max_severity, j.created_at, j.started_at, j.finished_at, searchableText(j.stats || {})].filter(Boolean).join(" ");
  }

  function draw() {
    const rows = data.filter(j => {
      if (kind.value && String(j.kind) !== kind.value) return false;
      if (store.value && String(j.store) !== store.value) return false;
      if (sev.value && !severityMeets(j.max_severity, sev.value)) return false;
      if (withFindings.checked && !Number(j.finding_count || 0)) return false;
      return fuzzyMatch(jobText(j), search.value);
    });
    count.textContent = `${number(rows.length)} of ${number(data.length)} loaded scans`;
    scanTable.setRows(rows.map(j => h("tr", {class: "archive-row"},
      h("td", {}, formatWhen(j.created_at)),
      h("td", {class: "mono archive-id"}, j.id),
      h("td", {class: "mono archive-store", title: j.store || ""}, storeLabel(j.store)),
      h("td", {}, j.kind || "-"),
      h("td", {}, badge(j.max_severity)),
      h("td", {}, number(j.finding_count)),
      h("td", {}, coverageChip(((j.stats || {}).coverage || {}).status)),
      h("td", {}, h("button", {class: "btn small", type: "button", "aria-label": `Open scan ${j.id}`,
                               onclick: () => showHistoryJob(j.id)}, "Open")))),
    {empty: data.length ? "No matching scans." : "No individual scans."});
  }

  const archiveFilters = {q: search, kind, scanstore: store, severity: sev};
  for (const [name, input] of Object.entries(archiveFilters)) {
    input.addEventListener(input.tagName === "SELECT" ? "change" : "input", () => {
      setParams({[name]: input.value});
      draw();
    });
  }
  withFindings.addEventListener("change", () => {
    setParams({findings: withFindings.checked ? "1" : null});
    draw();
  });
  withFindings.checked = param("findings") === "1";
  draw();
  return h("div", {class: "archive-view archive-scans"},
    toolbar("Filter scans", [
      h("div", {class: "search-field"}, icon("search"), search),
      kind,
      store,
      sev,
      h("label", {class: "switch-line compact"}, withFindings, "Only with findings", tooltip("Hide scans with zero recorded findings. Those scans may still have incomplete coverage or errors.")),
      count], {className: "archive-filters"}),
    scanTable.node);
}

function archiveRows(jobs) {
  return [...jobs].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
}

// A scan opens as its own page too (`#/history?scan=<id>`).
function showHistoryJob(id) {
  goTo("history", {scan: id, list: "scans"});
}

async function savedScanView(id) {
  const box = h("div", {class: "archive-view archive-detail"});
  box.append(pageHeader(recordTitle("Scan", id),
    "One recorded scan: what it covered and what it observed.", null,
    {back: {label: "All scans", className: "archive-back", onclick: () => climbOut("history")}}));
  let job;
  try {
    job = await api(`/admin/history/${encodeURIComponent(id)}`);
  } catch (e) {
    box.append(panel(`Scan ${id}`, errorState(unavailableReason(e), () => route())));
    return box;
  }
  const coverage = resultCoverageOf(job);
  const complete = coverage.complete === true && coverage.status === "complete";
  const findings = job.findings || [];
  const summary = {};
  for (const f of findings) summary[f.severity] = (summary[f.severity] || 0) + 1;
  box.append(recordHead({
    meta: [
      h("span", {class: "mono", title: job.store || ""}, storeLabel(job.store)),
      h("span", {}, job.kind || "scan"),
      formatWhen(job.created_at),
      coverageChip(coverage.status),
      severityCounts(summary, {complete})],
    action: job.audit_id
      ? h("button", {class: "btn", type: "button", onclick: () => goTo("history", {audit: job.audit_id})},
          icon("archive"), "Open its audit")
      : h("span", {class: "sub"}, "Standalone or legacy scan: no parent audit"),
    notes: [
      statusLine(coverageSentence(coverage), complete ? "info" : "medium"),
      job.has_more ? statusLine(`Showing the first ${number(findings.length)} findings of this scan.`, "medium") : ""],
  }));
  box.append(resultCoverage(job));
  box.append(panel(`Findings (${number(findings.length)})`, findingsTable(findings)));
  box.append(h("details", {class: "evidence-data"}, h("summary", {}, icon("code"), "Evidence data"), jsonBlock(job)));
  return box;
}

function findingSearchText(f) {
  return [
    f.id, f.job_id, f.store, f.collection, f.category, f.severity,
    f.title, f.description, f.remediation, f.fingerprint,
    searchableText(f.evidence || {}),
  ].filter(Boolean).join(" ");
}

const FINDINGS_TABLE_HEADERS = ["Severity", "Finding", "Scope", "Evidence", "Fingerprint"];

function findingsTable(findings) {
  const data = (findings || []).map(f => ({
    ...f,
    evidence: typeof f.evidence === "string" ? safeJson(f.evidence) : (f.evidence || {}),
  }));
  const search = textInput("", {placeholder: "Search findings and evidence", "aria-label": "Search findings and evidence"});
  const sev = selectInput([["", "Min severity"], ...uniqueValues(data, f => f.severity).map(x => [x, x])]);
  const cat = selectInput([["", "All categories"], ...uniqueValues(data, f => f.category).map(x => [x, categoryLabel(x)])]);
  const col = selectInput([["", "All collections"], ...uniqueValues(data, f => f.collection).map(x => [x, x])]);
  const store = selectInput([["", "All stores"], ...uniqueValues(data, f => f.store).map(x => [x, x])]);
  const label = selectInput([["", "All labels"], ...optionSet(data.flatMap(f => Object.keys((f.evidence || {}).label_counts || {})))]);
  const activeOnly = h("input", {type: "checkbox", "aria-label": "Hide suppressed findings"});
  const count = h("span", {class: "result-count"}, "");
  const tbody = h("tbody", {});

  function draw() {
    const rows = data.filter(f => {
      if (sev.value && !severityMeets(f.severity, sev.value)) return false;
      if (cat.value && String(f.category) !== cat.value) return false;
      if (col.value && String(f.collection) !== col.value) return false;
      if (store.value && String(f.store) !== store.value) return false;
      if (label.value && !Number(((f.evidence || {}).label_counts || {})[label.value] || 0)) return false;
      if (activeOnly.checked && f.suppressed) return false;
      return fuzzyMatch(findingSearchText(f), search.value);
    });
    count.textContent = `${number(rows.length)} of ${number(data.length)} findings`;
    tbody.replaceChildren(...(rows.length ? labelCells(FINDINGS_TABLE_HEADERS, rows.map(findingRow)) :
      [h("tr", {}, h("td", {colspan: 5}, h("div", {class: "empty"}, data.length ? "No matching findings." : "No findings.")))]));
  }

  [search, sev, cat, col, store, label].forEach(input => {
    input.addEventListener(input.tagName === "SELECT" ? "change" : "input", draw);
  });
  activeOnly.addEventListener("change", draw);
  draw();
  return h("div", {class: "findings-view"},
    h("div", {class: "findings-tools"},
      h("div", {class: "search-field"}, icon("search"), search),
      sev,
      cat,
      col,
      store,
      label,
      h("label", {class: "switch-line compact"}, activeOnly, "Active only", tooltip("Exclude findings that are tagged as suppressed or accepted risk.")),
      count),
    h("div", {class: "table-wrap"},
      h("table", {},
        h("thead", {}, h("tr", {}, FINDINGS_TABLE_HEADERS.map(tableHeader))),
        tbody)));
}

function findingRow(f) {
  const fingerprint = f.fingerprint || (f.evidence || {}).fingerprint || "-";
  const refs = chunkRefs(f);
  return h("tr", {},
    h("td", {}, badge(f.severity)),
    h("td", {},
      f.id
        ? h("button", {class: "link strong", type: "button", onclick: () => openFinding(f)}, f.title || f.id)
        : h("div", {class: "strong"}, f.title || "-"),
      refs.length
        ? h("div", {class: "sub"}, h("button", {class: "link", type: "button",
            onclick: () => openChunk({store: f.store, collection: f.collection,
                                      chunkId: refs[0].chunkId, finding: f})},
            icon("eye"), `Open chunk ${refs[0].chunkId}`),
            refs.length > 1 ? ` and ${number(refs.length - 1)} more` : "")
        : "",
      h("div", {class: "sub"}, f.description || ""),
      h("div", {class: "tag-row"}, h("span", {class: "tag", title: f.category || null}, f.category ? categoryLabel(f.category) : "uncategorized"), f.suppressed ? stateChip("medium", "suppressed") : "")),
    h("td", {}, findingLocation(f)),
    h("td", {}, evidenceView(f.evidence || {})),
    h("td", {class: "mono"}, fingerprint));
}

function safeJson(value) {
  try { return JSON.parse(value); } catch { return {}; }
}

// Ingest: try the three content checks on text before it is embedded. Nothing
// here writes to a store or enforces a pipeline; the page says so, and every
// result is worded as a preview ("would block"), qualified by the detection
// coverage the server reports for that run.
//
// The examples are synthetic: invented values, or documented test values such
// as the 4111 card and AWS's EXAMPLE key. Each one declares what the engine
// should report for it, and tests/test_ingest_examples.py runs every example
// against the API and fails when the two disagree. The block between the
// markers is strict JSON so that test can read it without a JavaScript parser.
// Loading an example only fills the editor; it never runs a check.
const INGEST_EXAMPLES = /* INGEST_EXAMPLES:BEGIN */ [
  {
    "id": "support-email", "version": 1, "category": "personal",
    "title": "Support reply with an email address",
    "explanation": "A support thread that includes a customer's email address.",
    "lesson": "Shows a personal-data finding and which chunk crosses the blocking threshold.",
    "chunks": ["Hi team, please reply to jordan.lee@example.com about ticket 4471."],
    "tasks": ["gate", "redact"],
    "suggested": {"task": "gate", "block_severity": "high"},
    "expected": {"gate": {"blocked": ["chunk-1"], "labels": ["pii"]}, "redact": {"min_spans": 1}},
    "limitations": "Recognising the address format says nothing about whose address it is.",
    "requires": "regex"
  },
  {
    "id": "callback-phone", "version": 1, "category": "personal",
    "title": "Call-back note with a phone number",
    "explanation": "An agent's note asking for a call back on a customer's number.",
    "lesson": "Shows a redaction preview replacing a phone number with a labelled token.",
    "chunks": ["Call the customer back on +1 415 555 0132 after 5pm."],
    "tasks": ["redact", "gate"],
    "suggested": {"task": "redact", "show_preview": true},
    "expected": {"gate": {"blocked": ["chunk-1"], "labels": ["pii"]}, "redact": {"min_spans": 1}},
    "limitations": "One number can match more than one phone pattern, so the replacement count can be higher than the number of values.",
    "requires": "regex"
  },
  {
    "id": "billing-test-card", "version": 1, "category": "payments",
    "title": "Billing note with a test card number",
    "explanation": "A billing note that records the card a customer paid with.",
    "lesson": "Shows a payment-data finding, then what redaction replaces.",
    "chunks": ["Billing note: the customer paid with test card 4111 1111 1111 1111, expiry 12/30."],
    "tasks": ["gate", "redact"],
    "suggested": {"task": "gate", "block_severity": "high"},
    "expected": {"gate": {"blocked": ["chunk-1"], "labels": ["pci"]}, "redact": {"min_spans": 1}},
    "limitations": "4111 1111 1111 1111 is a documented test number. A finding means the text has a card number's shape, not that the card is live.",
    "requires": "regex"
  },
  {
    "id": "refund-iban", "version": 1, "category": "payments",
    "title": "Refund to a bank account",
    "explanation": "A refund approval that names the destination IBAN.",
    "lesson": "Shows that bank account numbers are payment data too, not only cards.",
    "chunks": ["Refund approved to IBAN GB82 WEST 1234 5698 7654 32 for order 1182."],
    "tasks": ["gate", "redact"],
    "suggested": {"task": "gate", "block_severity": "high"},
    "expected": {"gate": {"blocked": ["chunk-1"], "labels": ["pci"]}, "redact": {"min_spans": 1}},
    "limitations": "The IBAN is the standard published example. Account numbers in national formats without an IBAN may not be recognised.",
    "requires": "regex"
  },
  {
    "id": "aws-example-key", "version": 1, "category": "credentials",
    "title": "Deployment note with a cloud access key",
    "explanation": "A runbook line that pastes an access key ID into the instructions.",
    "lesson": "Shows a credential finding, which blocks at Critical.",
    "chunks": ["Deploy with key AKIAIOSFODNN7EXAMPLE in the staging pipeline."],
    "tasks": ["gate", "redact"],
    "suggested": {"task": "gate", "block_severity": "high"},
    "expected": {"gate": {"blocked": ["chunk-1"], "labels": ["secret"]}, "redact": {"min_spans": 1}},
    "limitations": "AKIAIOSFODNN7EXAMPLE is AWS's documented example key. Matching a credential's pattern does not establish that the credential is live.",
    "requires": "regex"
  },
  {
    "id": "ci-token", "version": 1, "category": "credentials",
    "title": "CI instructions with a personal access token",
    "explanation": "Build instructions that include an invented token in GitHub's format.",
    "lesson": "Shows that a token with a recognisable prefix is caught as a secret.",
    "chunks": ["Use token ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5 for the CI job."],
    "tasks": ["gate", "redact"],
    "suggested": {"task": "gate", "block_severity": "high"},
    "expected": {"gate": {"blocked": ["chunk-1"], "labels": ["secret"]}, "redact": {"min_spans": 1}},
    "limitations": "Detection relies on the token's format. A secret with no recognisable prefix or structure may not be found.",
    "requires": "regex"
  },
  {
    "id": "clinical-note", "version": 1, "category": "health",
    "title": "Clinical note with patient identifiers",
    "explanation": "A visit note that names a patient with a record number and date of birth.",
    "lesson": "Shows health data found through identifiers in a clinical context.",
    "chunks": ["Patient Dana Ruiz, MRN 4839201, DOB 1984-03-12, was seen for a diabetes follow-up."],
    "tasks": ["gate", "redact"],
    "suggested": {"task": "gate", "block_severity": "high"},
    "expected": {"gate": {"blocked": ["chunk-1"], "labels": ["phi"]}, "redact": {"min_spans": 1}},
    "limitations": "Detection keys on identifiers such as a record number or date of birth next to clinical wording. It is not broad medical-text coverage, and a diagnosis alone is not flagged.",
    "requires": "regex"
  },
  {
    "id": "mixed-thread", "version": 1, "category": "mixed",
    "title": "Support thread with mixed chunks",
    "explanation": "Three chunks from one conversation: an ordinary reply, a contact detail, and a card number.",
    "lesson": "Shows a decision per chunk, and why only some cross the threshold.",
    "chunks": [
      "Thanks for waiting. Your refund has been processed.",
      "You can reach me at jordan.lee@example.com.",
      "The card was entered as 4111 1111 1111 1111."
    ],
    "tasks": ["gate", "redact"],
    "suggested": {"task": "gate", "block_severity": "high"},
    "expected": {"gate": {"blocked": ["chunk-2", "chunk-3"], "labels": ["pci", "pii"]}, "redact": {"min_spans": 2}},
    "limitations": "The first chunk has no finding for the checks that ran. That is not proof that it holds nothing sensitive.",
    "requires": "regex"
  },
  {
    "id": "contact-redaction", "version": 1, "category": "mixed",
    "title": "Contact line with three kinds of value",
    "explanation": "One line holding an email address, a phone number, and a card number.",
    "lesson": "Shows every recognised value replaced, each with its own label.",
    "chunks": ["Contact jordan.lee@example.com or call +1 415 555 0132; card 4111 1111 1111 1111."],
    "tasks": ["redact", "gate"],
    "suggested": {"task": "redact", "show_preview": true},
    "expected": {"gate": {"blocked": ["chunk-1"], "labels": ["pci"]}, "redact": {"min_spans": 3}},
    "limitations": "A chunk's check reports its most serious label only, so the payment finding hides the personal data beside it. Redaction replaces all three.",
    "requires": "regex"
  },
  {
    "id": "refund-status", "version": 1, "category": "benign",
    "title": "Refund status message",
    "explanation": "An ordinary customer message with no supported sensitive pattern.",
    "lesson": "Shows what \"no blocking findings\" means, and what it does not mean.",
    "chunks": ["Your refund has been processed and should arrive within 3 to 5 business days."],
    "tasks": ["gate", "redact"],
    "suggested": {"task": "gate", "block_severity": "high"},
    "expected": {"gate": {"blocked": [], "labels": []}, "redact": {"min_spans": 0, "max_spans": 0}},
    "limitations": "No findings means none of the checks that ran matched. It does not show that the text is safe to embed.",
    "requires": "regex"
  },
  {
    "id": "split-ssn", "version": 1, "category": "boundaries",
    "title": "Identifier split across two chunks",
    "explanation": "A chunker cut a US social security number in half between two chunks.",
    "lesson": "Shows why checking each chunk separately can miss a value that the boundary check finds.",
    "chunks": ["Customer SSN is 219-09-", "9999 on file."],
    "tasks": ["boundaries", "gate"],
    "suggested": {"task": "boundaries", "zone_chars": 64},
    "expected": {"gate": {"blocked": [], "labels": []}, "boundaries": {"labels": ["pii"]}},
    "limitations": "The boundary check joins only adjacent chunks, within the window. A value split across non-adjacent chunks, or longer than the window, is not reconstructed.",
    "requires": "regex"
  },
  {
    "id": "split-card", "version": 1, "category": "boundaries",
    "title": "Card number split across two chunks",
    "explanation": "A card number broken across a chunk boundary, with neither half recognisable alone.",
    "lesson": "Shows a payment value that appears only when the boundary is joined.",
    "chunks": ["Card on file: 4111 1111", "1111 1111 expires 12/30."],
    "tasks": ["boundaries", "gate"],
    "suggested": {"task": "boundaries", "zone_chars": 64},
    "expected": {"gate": {"blocked": [], "labels": []}, "boundaries": {"labels": ["pci"]}},
    "limitations": "Chunk order matters: the check assumes the chunks are consecutive parts of one document, in the order given.",
    "requires": "regex"
  }
] /* INGEST_EXAMPLES:END */;

const INGEST_CATEGORIES = [
  ["personal", "Personal data"], ["payments", "Payments"], ["credentials", "Credentials and secrets"],
  ["health", "Health context"], ["mixed", "Mixed content"], ["benign", "Benign content"],
  ["boundaries", "Chunk boundaries"],
];

const INGEST_TASKS = [
  {id: "gate", label: "Check content", run: "Check content", path: "/ingest/gate",
   blurb: "Classify each chunk and see which ones a gate would block at the severity you choose.",
   before: "Run the check to see, chunk by chunk, what would be blocked at the selected severity, the masked values that matched, and which detectors ran."},
  {id: "redact", label: "Preview redaction", run: "Preview redaction", path: "/ingest/redact",
   blurb: "Replace each recognised sensitive value with a labelled token, and see the text that would remain.",
   before: "Run the preview to see how many values were replaced and, if you ask for it, the redacted text of each chunk."},
  {id: "boundaries", label: "Check chunk boundaries", run: "Check boundaries", path: "/ingest/analyze-boundaries",
   blurb: "Find values split between two adjacent chunks of one document, which checking each chunk separately misses.",
   before: "Run the check to see any value that only appears when two adjacent chunks are joined, with the pair it was split across."},
];

// The console's own limit. The gate classifies at most 5,000 characters of each
// text surface, so a longer chunk would be checked only in part while reading as
// checked in full. Refusing it with a reason is honest; truncating it is not.
const INGEST_CHUNK_LIMIT = 5000;

function severityName(value) {
  const s = String(value || "");
  return s ? s[0].toUpperCase() + s.slice(1) : "-";
}

function ingestChunkName(id) {
  const match = /^chunk-(\d+)$/.exec(String(id || ""));
  return match ? `Chunk ${match[1]}` : String(id || "-");
}

function ingestTask(id) {
  return INGEST_TASKS.find(t => t.id === id) || INGEST_TASKS[0];
}

async function renderIngest() {
  const s = {
    task: ingestTask(param("task")).id,
    category: INGEST_CATEGORIES.some(([id]) => id === param("category")) ? param("category") : "",
    example: null,
    chunks: [""],
    // True once the editor holds text the reader wrote or changed, so loading
    // an example over it asks first.
    edited: false,
    settings: {block_severity: "high", mode: "soft", show_preview: true, zone_chars: "64"},
    running: false,
    seq: 0,
    // One result per task: switching tabs shows that task's last result,
    // marked stale if the input or its settings changed since.
    results: {},
  };
  const linked = INGEST_EXAMPLES.find(e => e.id === param("example"));
  if (linked) {
    s.example = linked;
    s.chunks = [...linked.chunks];
  }

  const box = h("div", {class: "ingest"});
  box.append(pageHeader("ingest", "Try sensitive-content checks before embedding."));

  // Task tabs. Every tab stays in the tab sequence (the keyboard gate forbids
  // tabindex=-1 on controls); arrow keys move between them as well.
  const taskTabs = tabList({id: "ingest", label: "Ingest task", className: "tabs ingest-tabs",
                            tabs: INGEST_TASKS.map(t => [t.id, t.label]), current: s.task,
                            panelId: "ingest-task-panel", panelClass: "ingest-task", dataKey: "task",
                            onSelect: id => selectTask(id)});
  const taskBlurb = h("p", {class: "muted ingest-blurb"});
  const taskPanel = taskTabs.panel;

  const picker = h("details", {class: "ingest-picker"});
  const editor = h("div", {class: "ingest-editor"});
  // The example's own note stays in view; the task's settings fold away
  // under a summary that names their current values.
  const exampleBox = h("div", {class: "ingest-example"});
  const settingsBox = h("div", {class: "ingest-settings"});
  const settingsNow = h("span", {class: "sub ingest-settings-now"});
  const settingsFold = h("details", {class: "evidence-data ingest-settings-fold"},
    h("summary", {}, icon("sliders"), h("span", {}, "Settings"), " ", settingsNow),
    settingsBox);
  const problemsBox = h("div", {class: "ingest-problems", id: "ingest-problems"});
  const runButton = h("button", {class: "btn primary", type: "submit"});
  const resultBox = h("div", {class: "ingest-result"});

  const form = h("form", {class: "ingest-input", "aria-labelledby": "ingest-input-title",
    onsubmit: event => { event?.preventDefault?.(); run(); }},
    editor, exampleBox, settingsFold, problemsBox,
    h("div", {class: "bar ingest-run"}, runButton));

  taskPanel.append(taskBlurb, picker,
    h("div", {class: "ingest-work"},
      panel("Input", form, null, {headingId: "ingest-input-title"}),
      panel("Result", [resultBox,
        statusLine("These checks do not write to a vector store or enforce your pipeline. " +
                   "Operation counts are recorded in the audit log.", "info")],
        null, {headingId: "ingest-result-title", className: "ingest-result-panel"})));
  box.append(taskTabs.bar, taskPanel);

  // ---- examples -------------------------------------------------------------

  function drawPicker() {
    const shown = INGEST_EXAMPLES.filter(e => !s.category || e.category === s.category);
    const chip = ([id, label]) => h("button", {
      class: `chip${s.category === id ? " chip-on" : ""}`, type: "button",
      "aria-pressed": String(s.category === id),
      onclick: () => { s.category = id; setParams({category: id}); drawPicker(); },
    }, label);
    picker.replaceChildren(
      h("summary", {}, icon("layers"),
        s.example
          ? h("span", {}, "Example: ", h("strong", {}, s.example.title), h("span", {class: "sub"}, " · Change example"))
          : h("span", {}, "Use an example")),
      h("div", {class: "ingest-picker-body"},
        h("div", {class: "ingest-picker-head"},
          h("span", {class: "sub"}, "Synthetic examples. Loading one fills the editor; nothing runs until you choose to."),
          h("button", {class: "btn small", type: "button", onclick: ownContent}, icon("edit"), "Paste my own content")),
        h("div", {class: "chip-row", role: "group", "aria-label": "Example category"},
          chip(["", "All"]), INGEST_CATEGORIES.map(chip)),
        h("div", {class: "ingest-examples", role: "list", "aria-label": "Example"},
          shown.map(example => h("div", {role: "listitem"}, h("button", {
            class: `example-card${s.example?.id === example.id ? " is-loaded" : ""}`, type: "button",
            "aria-pressed": String(s.example?.id === example.id),
            onclick: () => loadExample(example),
          },
            h("span", {class: "example-cat"}, INGEST_CATEGORIES.find(([id]) => id === example.category)?.[1] || example.category),
            h("span", {class: "strong"}, example.title),
            h("span", {class: "sub"}, example.lesson),
            h("span", {class: "example-meta"},
              `Suggested: ${ingestTask(example.suggested.task).label} · ${plural(example.chunks.length, "chunk")}`)))))));
  }

  function replaceContent(apply, what) {
    if (!s.edited || !s.chunks.some(c => c.trim())) { apply(); return; }
    const keep = h("button", {class: "btn", type: "button", onclick: closeModal}, "Keep my content");
    const replace = h("button", {class: "btn primary", type: "button",
      onclick: () => { closeModal(); apply(); }}, "Replace");
    modal("Replace your content?", h("div", {},
      h("p", {}, `The editor holds text you wrote or changed. ${what} replaces it, and it cannot be recovered afterwards.`)),
      null, "", {actions: [keep, replace]});
  }

  function loadExample(example) {
    replaceContent(() => {
      s.example = example;
      s.chunks = [...example.chunks];
      s.edited = false;
      setParams({example: example.id});
      picker.open = false;
      drawPicker(); drawEditor(); drawSettings(); refreshResult();
      announce(`Example loaded: ${example.title}. Nothing has run yet.`);
      picker.querySelector("summary")?.focus?.();
    }, "Loading this example");
  }

  function ownContent() {
    replaceContent(() => {
      s.example = null;
      s.chunks = [""];
      s.edited = false;
      setParams({example: ""});
      picker.open = false;
      drawPicker(); drawEditor(); drawSettings(); refreshResult();
      editor.querySelector("textarea")?.focus?.();
    }, "Starting blank");
  }

  // ---- chunk editor ---------------------------------------------------------

  function drawEditor() {
    const bulkArea = h("textarea", {id: "ingest-bulk", rows: "5", spellcheck: "false"});
    const bulkNote = h("p", {class: "sub", id: "ingest-bulk-note"});
    bulkArea.setAttribute("aria-describedby", "ingest-bulk-note");
    const splitBulk = () => bulkArea.value.split(/\n{2,}/).filter(part => part.trim());
    const syncBulk = () => {
      const n = splitBulk().length;
      bulkNote.textContent = "Blank lines separate chunks; a single line break stays inside a chunk. " +
        (n ? `This makes ${plural(n, "chunk")}.` : "");
    };
    bulkArea.addEventListener("input", syncBulk);
    syncBulk();
    editor.replaceChildren(
      h("div", {class: "ingest-chunks", role: "list", "aria-label": "Chunks"},
        s.chunks.map((_, index) => chunkEditor(index))),
      h("div", {class: "bar ingest-editor-actions"},
        h("button", {class: "btn small", type: "button", onclick: () => {
          s.chunks.push("");
          s.edited = true;
          drawEditor(); onDraftChange();
          const areas = editor.querySelectorAll(".chunk-editor textarea");
          areas[areas.length - 1]?.focus?.();
        }}, icon("plus"), "Add chunk"),
        h("span", {class: "sub"}, plural(s.chunks.length, "chunk"))),
      h("details", {class: "evidence-data ingest-bulk"},
        h("summary", {}, icon("list"), "Paste several chunks at once"),
        h("label", {class: "field", for: "ingest-bulk"}, h("span", {}, "Text to split into chunks")),
        bulkArea, bulkNote,
        h("button", {class: "btn small", type: "button", onclick: () => {
          const parts = splitBulk();
          if (!parts.length) { bulkNote.textContent = "Paste some text first."; return; }
          replaceContent(() => {
            s.chunks = parts;
            s.edited = true;
            drawEditor(); onDraftChange();
            announce(`Replaced the editor with ${plural(parts.length, "chunk")}.`);
          }, "Splitting this text");
        }}, "Replace chunks with this text")));
  }

  function chunkEditor(index) {
    const id = `ingest-chunk-${index + 1}`;
    const area = h("textarea", {id, rows: "3", spellcheck: "false", "aria-describedby": `${id}-count`});
    area.value = s.chunks[index];
    const counter = h("span", {class: "chunk-count", id: `${id}-count`});
    const sync = () => {
      const length = area.value.length;
      const over = length > INGEST_CHUNK_LIMIT;
      counter.textContent = over
        ? `${number(length)} / ${number(INGEST_CHUNK_LIMIT)} characters: ${number(length - INGEST_CHUNK_LIMIT)} over. Split or shorten this chunk.`
        : `${number(length)} / ${number(INGEST_CHUNK_LIMIT)} characters`;
      counter.classList.toggle("is-over", over);
      over ? area.setAttribute("aria-invalid", "true") : area.removeAttribute("aria-invalid");
    };
    area.addEventListener("input", () => {
      s.chunks[index] = area.value;
      s.edited = true;
      sync(); onDraftChange();
    });
    sync();
    return h("div", {class: "chunk-editor", role: "listitem"},
      h("div", {class: "chunk-head"},
        h("label", {for: id, class: "strong"}, `Chunk ${index + 1}`),
        counter,
        s.chunks.length > 1
          ? h("button", {class: "btn small", type: "button", "aria-label": `Remove chunk ${index + 1}`,
              onclick: () => {
                s.chunks.splice(index, 1);
                s.edited = true;
                drawEditor(); onDraftChange();
                const areas = editor.querySelectorAll(".chunk-editor textarea");
                areas[Math.min(index, areas.length - 1)]?.focus?.();
              }}, icon("trash"), "Remove")
          : ""),
      area);
  }

  // ---- settings -------------------------------------------------------------

  function suggestionDiffs(example) {
    const out = [];
    const suggested = example.suggested || {};
    if (suggested.task && suggested.task !== s.task) out.push(`the ${ingestTask(suggested.task).label} task`);
    const t = suggested.task || s.task;
    if (t === s.task) {
      if (t === "gate" && suggested.block_severity && suggested.block_severity !== s.settings.block_severity) {
        out.push(`blocking at ${severityName(suggested.block_severity)} or above`);
      }
      if (t === "redact" && suggested.show_preview != null && suggested.show_preview !== s.settings.show_preview) {
        out.push(suggested.show_preview ? "showing the redacted text" : "counts only");
      }
      if (t === "boundaries" && suggested.zone_chars != null && String(suggested.zone_chars) !== String(s.settings.zone_chars)) {
        out.push(`a ${number(suggested.zone_chars)}-character boundary window`);
      }
    }
    return out;
  }

  function applySuggestion(example) {
    const suggested = example.suggested || {};
    if (suggested.block_severity) s.settings.block_severity = suggested.block_severity;
    if (suggested.show_preview != null) s.settings.show_preview = suggested.show_preview;
    if (suggested.zone_chars != null) s.settings.zone_chars = String(suggested.zone_chars);
    if (suggested.task && suggested.task !== s.task) selectTask(suggested.task);
    else { drawSettings(); refreshResult(); }
    announce("Suggested settings applied.");
  }

  function drawSettings() {
    const parts = [];
    exampleBox.replaceChildren();
    if (s.example) {
      const diffs = suggestionDiffs(s.example);
      exampleBox.append(h("div", {class: "ingest-example-note"},
        h("p", {class: "strong"}, s.example.title),
        h("p", {class: "muted"}, s.example.explanation),
        h("p", {class: "sub"}, h("strong", {}, "What to look for: "), s.example.lesson),
        h("p", {class: "sub"}, h("strong", {}, "Limits: "), s.example.limitations),
        s.example.tasks.includes(s.task)
          ? ""
          : statusLine(`This example is not written for ${ingestTask(s.task).label}; its description may not match what this task reports.`, "medium"),
        diffs.length
          ? h("div", {class: "bar ingest-suggest"},
              statusLine(`The example suggests ${diffs.join(" and ")}. With the current settings, its result may differ from what it describes.`, "medium"),
              h("button", {class: "btn small", type: "button", onclick: () => applySuggestion(s.example)}, "Apply suggested settings"))
          : ""));
    }
    if (s.task === "gate") {
      const severity = selectInput(severityOrder.map(v => [v, `${severityName(v)} or above`]), s.settings.block_severity,
        {id: "ingest-severity", "aria-describedby": "ingest-severity-help"});
      severity.addEventListener("change", () => { s.settings.block_severity = severity.value; onDraftChange(); drawSettingsNote(); });
      const mode = selectInput([["soft", "Soft: report and let the caller decide"], ["hard", "Hard: the caller rejects the whole batch"]],
        s.settings.mode, {id: "ingest-mode", "aria-describedby": "ingest-mode-help"});
      mode.addEventListener("change", () => { s.settings.mode = mode.value; drawSettingsNow(); onDraftChange(); });
      parts.push(
        h("label", {class: "field"}, h("span", {}, "Block at severity"), severity),
        h("p", {class: "sub", id: "ingest-severity-help"},
          "A chunk would be blocked when its most serious finding is at or above this severity. Findings below it are not reported by this check."),
        // Already inside the folded settings, so the caller mode needs no
        // second disclosure of its own.
        h("label", {class: "field"}, h("span", {}, "Caller mode"), mode),
        h("p", {class: "sub", id: "ingest-mode-help"},
          "How an ingestion pipeline calling the gate would act on the same result. This preview runs the same check in either mode and blocks nothing."));
    } else if (s.task === "redact") {
      const preview = h("input", {type: "checkbox", id: "ingest-preview", checked: s.settings.show_preview,
        "aria-describedby": "ingest-preview-help"});
      preview.addEventListener("change", () => { s.settings.show_preview = preview.checked; drawSettingsNow(); onDraftChange(); });
      parts.push(
        h("label", {class: "check-row", for: "ingest-preview"}, preview, h("span", {}, "Show the redacted text")),
        h("p", {class: "sub", id: "ingest-preview-help"},
          "Off returns counts only: the server sends back how many values it replaced, and no chunk text."));
    } else {
      const zone = textInput(s.settings.zone_chars, {type: "number", min: "1", max: String(INGEST_CHUNK_LIMIT), step: "1",
        id: "ingest-zone", inputmode: "numeric", "aria-describedby": "ingest-zone-help"});
      zone.addEventListener("input", () => { s.settings.zone_chars = zone.value; drawSettingsNow(); onDraftChange(); });
      parts.push(
        h("label", {class: "field", for: "ingest-zone"}, h("span", {}, "Boundary window (characters)"), zone),
        h("p", {class: "sub", id: "ingest-zone-help"},
          "How many characters each side of a boundary are joined and checked. The chunks are treated as consecutive parts of one document, in the order shown; you need at least two."));
    }
    settingsBox.replaceChildren(...parts);
    drawSettingsNow();
    runButton.replaceChildren(icon("play"), ingestTask(s.task).run);
    syncRun();
  }

  // The folded settings say what they are set to, so nobody has to open them
  // to know what a run will use.
  function drawSettingsNow() {
    settingsNow.textContent = "· " + (s.task === "gate"
      ? `Blocks at ${severityName(s.settings.block_severity)} or above · ${s.settings.mode === "hard" ? "hard" : "soft"} caller`
      : s.task === "redact"
        ? (s.settings.show_preview ? "Shows the redacted text" : "Counts only")
        : `${String(s.settings.zone_chars).trim() || "No"}-character boundary window`);
  }

  // Changing the threshold changes the explanation beneath the result too.
  function drawSettingsNote() { drawSettingsNow(); refreshResult(); }

  // ---- validation and running ---------------------------------------------

  function problems() {
    const out = [];
    const filled = s.chunks.filter(c => c.trim());
    if (!filled.length) out.push({text: "Add some text to a chunk first.", target: 0});
    else {
      s.chunks.forEach((c, i) => {
        if (!c.trim() && s.chunks.length > 1) out.push({text: `Chunk ${i + 1} is empty. Add text or remove it.`, target: i});
      });
    }
    s.chunks.forEach((c, i) => {
      if (c.length > INGEST_CHUNK_LIMIT) {
        out.push({text: `Chunk ${i + 1} is ${number(c.length - INGEST_CHUNK_LIMIT)} characters over the ${number(INGEST_CHUNK_LIMIT)}-character limit. Split it into more chunks or shorten it.`, target: i});
      }
    });
    if (s.task === "boundaries") {
      if (s.chunks.length < 2) out.push({text: "A boundary check needs at least two consecutive chunks from the same document. Add a chunk.", target: null});
      const raw = String(s.settings.zone_chars).trim();
      const zone = Number(raw);
      if (!/^\d+$/.test(raw) || zone < 1 || zone > INGEST_CHUNK_LIMIT) {
        out.push({text: `The boundary window must be a whole number of characters from 1 to ${number(INGEST_CHUNK_LIMIT)}.`, target: "zone"});
      }
    }
    return out;
  }

  function showProblems(list) {
    problemsBox.replaceChildren(list.length
      ? h("div", {class: "note note-error", role: "alert"},
          h("span", {class: "note-icon sev-error"}, icon("sev-critical")),
          h("div", {class: "note-text"},
            h("p", {}, list.length === 1 ? "Fix this before running:" : `Fix these ${number(list.length)} things before running:`),
            h("ul", {}, list.map(p => h("li", {}, p.text)))))
      : "");
    if (list.length) {
      const first = list[0];
      // The window is inside the folded settings: a problem with it opens
      // them, so the field it names can be seen and reached.
      if (list.some(p => p.target === "zone")) settingsFold.open = true;
      if (first.target === "zone") document.getElementById("ingest-zone")?.focus?.();
      else if (typeof first.target === "number") editor.querySelectorAll(".chunk-editor textarea")[first.target]?.focus?.();
    }
  }

  function signature() {
    const settings = s.task === "gate" ? [s.settings.block_severity, s.settings.mode]
      : s.task === "redact" ? [s.settings.show_preview] : [s.settings.zone_chars];
    return JSON.stringify([s.task, s.chunks, settings]);
  }

  function syncRun() {
    runButton.disabled = s.running;
    runButton.setAttribute("aria-busy", String(s.running));
  }

  function onDraftChange() {
    if (problemsBox.childNodes.length) showProblems(problems());
    refreshResult();
  }

  async function run() {
    if (s.running) return;
    const issues = problems();
    showProblems(issues);
    if (issues.length) return;
    const task = ingestTask(s.task);
    const chunks = s.chunks.map((text, i) => ({id: `chunk-${i + 1}`, text, collection: "console", metadata: {}}));
    const body = {chunks};
    if (task.id === "gate") Object.assign(body, {mode: s.settings.mode, block_severity: s.settings.block_severity});
    if (task.id === "redact") body.show_preview = Boolean(s.settings.show_preview);
    if (task.id === "boundaries") body.zone_chars = Number(s.settings.zone_chars);
    const sig = signature();
    const settings = {...s.settings};
    const seq = ++s.seq;
    s.running = true;
    syncRun();
    resultBox.replaceChildren(loadingState(`Running ${task.label}`));
    try {
      const data = await api(task.path, {method: "POST", body: JSON.stringify(body)});
      // A newer run, or a page that has since been left, owns the result area.
      if (seq !== s.seq) return;
      s.results[task.id] = {task: task.id, data, signature: sig, settings, chunkIds: chunks.map(c => c.id)};
      if (s.task === task.id) refreshResult();
      announce(ingestSummary(s.results[task.id]));
    } catch (e) {
      if (seq !== s.seq) return;
      delete s.results[task.id];
      if (s.task === task.id) {
        const restricted = e.status === 401 || e.status === 403;
        resultBox.replaceChildren(
          errorState(`${task.label} did not run: ${unavailableReason(e)}`, () => run()),
          statusLine(restricted
            ? (state.auth.login_enabled ? "Sign in again or ask an admin for access; your input is still here."
                                        : "Enter a bearer token in the header, then retry. Your input is still here.")
            : "Your input and settings are unchanged. Nothing was checked, so there is no result to show.", "info"));
      }
    } finally {
      if (seq === s.seq) { s.running = false; syncRun(); }
    }
  }

  // ---- results --------------------------------------------------------------

  function refreshResult() {
    const task = ingestTask(s.task);
    const result = s.results[task.id];
    if (s.running && !result) return;
    if (!result) {
      resultBox.replaceChildren(h("div", {class: "ingest-before"},
        h("p", {class: "muted"}, task.before),
        h("p", {class: "sub"}, "Nothing has run yet, so there are no findings to count.")));
      return;
    }
    const stale = result.signature !== signature();
    resultBox.replaceChildren(h("div", {class: `ingest-outcome${stale ? " is-stale" : ""}`},
      stale ? statusLine("The input or settings changed after this result. Run the check again to update it.", "medium") : "",
      task.id === "gate" ? gateOutcome(result) : task.id === "redact" ? redactOutcome(result) : boundaryOutcome(result),
      detectionCoverage(result.data.detection),
      h("details", {class: "evidence-data"},
        h("summary", {}, icon("code"), "Response data"),
        jsonBlock(result.data))));
  }

  function nextAction(label, glyph, onclick, note) {
    return h("div", {class: "ingest-next"},
      h("button", {class: "btn small", type: "button", onclick}, icon(glyph), label),
      note ? h("span", {class: "sub"}, note) : "");
  }

  function gateOutcome(result) {
    const data = result.data;
    const total = Number(data.total || 0);
    const blocked = Number(data.blocked || 0);
    const sev = severityName(result.settings.block_severity);
    const byChunk = new Map();
    for (const f of data.findings || []) {
      const id = (f.evidence || {}).chunk_id;
      if (id) byChunk.set(id, f);
    }
    const blockedIds = new Set(data.blocked_chunk_ids || []);
    const rows = result.chunkIds.map(id => {
      const f = byChunk.get(id);
      const ev = (f && f.evidence) || {};
      const previews = [...new Set((ev.spans || []).map(sp => sp.preview).filter(Boolean))];
      return h("tr", {},
        h("td", {}, ingestChunkName(id)),
        h("td", {}, blockedIds.has(id)
          ? stateChip("high", "would block")
          : stateChip("info", "no blocking finding")),
        h("td", {}, f
          ? h("div", {}, badge(f.severity), " ", h("span", {class: "tag"}, String(ev.label || "").toUpperCase()),
              h("div", {class: "sub"}, (ev.detectors || []).join(", ")))
          : h("span", {class: "sub"}, `nothing at ${sev} or above`)),
        h("td", {}, previews.length
          ? previews.map(p => h("div", {class: "mono"}, p))
          : h("span", {class: "sub"}, "-")));
    });
    return h("div", {},
      h("p", {class: "ingest-headline"}, blocked
        ? `Would block ${number(blocked)} of ${plural(total, "chunk")} at ${sev} or above`
        : "No blocking findings at this threshold"),
      h("p", {class: "sub"}, blocked
        ? (result.settings.mode === "hard"
            ? "A hard-mode caller would reject this whole batch. Nothing was blocked here: this is a preview."
            : "A soft-mode caller would receive this report and decide what to do. Nothing was blocked here: this is a preview.")
        : `${plural(total, "chunk")} checked at ${sev} or above. This covers the detectors that ran, not every kind of sensitive content.`),
      table(["Chunk", "Decision", "Finding", "Masked match"], rows),
      h("p", {class: "sub"}, "Matched values are masked by the server. Findings below the threshold are not reported."),
      blocked
        ? nextAction("Preview redaction of these chunks", "shield", () => selectTask("redact"),
            "Same chunks, same order. Nothing runs until you choose to.")
        : "");
  }

  function redactOutcome(result) {
    const data = result.data;
    const n = Number(data.spans_redacted || 0);
    const chunks = Array.isArray(data.chunks) ? data.chunks : null;
    const tokens = text => (String(text || "").match(/\[REDACTED:[A-Z_]+\]/g) || []).length;
    return h("div", {},
      h("p", {class: "ingest-headline"}, n
        ? `${plural(n, "match", "matches")} replaced across ${plural(result.chunkIds.length, "chunk")}`
        : "Nothing was replaced"),
      h("p", {class: "sub"}, n
        ? "The count is of detector matches. One value can match more than one detector, so there can be fewer tokens in the text than matches."
        : "Only values the detectors recognise are replaced. This does not show the text is free of sensitive content."),
      chunks
        ? table(["Chunk", "Tokens", "Redacted text"], chunks.map(c => h("tr", {},
            h("td", {}, ingestChunkName(c.id)),
            h("td", {}, number(tokens(c.text))),
            h("td", {}, h("div", {class: "mono ingest-redacted"}, c.text || "")))))
        : statusLine("Counts only: the server returned no chunk text. Turn on \"Show the redacted text\" and run again to see it.", "info"),
      statusLine("A preview replaces the values the detectors recognised. Anything they did not recognise remains, so this is not verified anonymisation.", "medium"),
      chunks && chunks.length
        ? nextAction("Load redacted text and check it", "play", () => checkRedacted(chunks),
            "Replaces the editor content with the redacted text, then runs Check content on it.")
        : "");
  }

  function checkRedacted(chunks) {
    s.chunks = chunks.map(c => String(c.text || ""));
    s.edited = true;
    s.example = null;
    setParams({example: ""});
    drawPicker(); drawEditor();
    selectTask("gate");
    announce("The editor now holds the redacted text.");
    run();
  }

  function boundaryOutcome(result) {
    const data = result.data;
    const findings = data.findings || [];
    const pairs = Math.max(0, result.chunkIds.length - 1);
    const zone = number(result.settings.zone_chars);
    return h("div", {},
      h("p", {class: "ingest-headline"}, findings.length
        ? `${plural(findings.length, "value")} split across a chunk boundary`
        : `No split values found at the ${plural(pairs, "boundary", "boundaries")} checked`),
      h("p", {class: "sub"}, `Window: ${zone} characters each side of each boundary.`),
      findings.length
        ? table(["Boundary", "Finding", "Masked value"], findings.map(f => {
            const ev = f.evidence || {};
            return h("tr", {},
              h("td", {}, `${ingestChunkName(ev.left_chunk)} → ${ingestChunkName(ev.right_chunk)}`),
              h("td", {}, badge(f.severity), " ", h("span", {class: "tag"}, String(ev.label || "").toUpperCase()),
                h("div", {class: "sub"}, ev.detector || "")),
              h("td", {}, h("span", {class: "mono"}, ev.preview || "-")));
          }))
        : h("p", {class: "sub"}, "Only adjacent pairs are joined, within the window. A value split further apart is not reconstructed."),
      findings.length
        ? statusLine("Checking each chunk on its own misses these. Chunking with an overlap keeps such values whole, so a per-chunk check can see them.", "info")
        : "");
  }

  function ingestSummary(result) {
    const data = result.data;
    if (result.task === "gate") {
      return Number(data.blocked || 0)
        ? `Would block ${number(data.blocked)} of ${plural(data.total, "chunk")}.`
        : "No blocking findings at this threshold.";
    }
    if (result.task === "redact") return `${plural(data.spans_redacted, "match", "matches")} replaced.`;
    return `${plural((data.findings || []).length, "split value")} found.`;
  }

  // ---- tabs -----------------------------------------------------------------

  function selectTask(id) {
    s.task = ingestTask(id).id;
    setParams({task: s.task === "gate" ? "" : s.task});
    taskTabs.select(s.task);
    taskBlurb.textContent = ingestTask(s.task).blurb;
    problemsBox.replaceChildren();
    drawSettings();
    refreshResult();
  }

  picker.open = !s.example;
  drawPicker();
  drawEditor();
  selectTask(s.task);
  return box;
}

// What detection ran for this result. A result with no findings means little
// without it: degraded NLP, or pattern detectors only, narrows what "nothing
// found" covers, and an absent record means coverage is unknown, not complete.
function detectionCoverage(detection) {
  if (!detection || typeof detection !== "object") {
    return statusLine("The response did not say which detectors ran, so what this result covers is unknown.", "unknown");
  }
  const patterns = detection.regex_detector_count
    ? plural(detection.regex_detector_count, "pattern detector")
    : "the pattern detectors";
  const status = String(detection.status || "unknown");
  // Checked before nlp_loaded: a loaded model that is not yet verified is not
  // one whose results can be counted on.
  if (status === "unverified") {
    return statusLine(`Detection: ${patterns}, plus a local NLP model that is not yet verified. A result with no findings is not a complete check.`, "medium");
  }
  if (status === "loading") {
    return statusLine(`Detection: ${patterns}. The local NLP model is still loading, so kinds of data that need it (such as personal names) may not have been checked.`, "info");
  }
  if (detection.nlp_loaded) {
    const model = [detection.active_model, detection.model_version].filter(Boolean).join(" ");
    return statusLine(`Detection: ${patterns} plus the local NLP model${model ? ` ${model}` : ""}.`, "info");
  }
  if (status === "disabled") {
    return statusLine(`Detection: ${patterns} only. Local NLP detection is off in this deployment, so kinds of data that need it (such as personal names) were not checked.`, "info");
  }
  if (status === "degraded") {
    return statusLine(`Coverage degraded: ${detection.reason || "the local NLP model is unavailable"}. Only ${patterns} ran, so a result with no findings is not a complete check.`, "medium");
  }
  return statusLine(`Detection status: ${humanize(status).toLowerCase()}. Only ${patterns} are known to have run.`, "unknown");
}

async function renderPolicies() {
  await loadCore();
  const box = h("div", {});
  const originOf = p => {
    const template = state.templates.find(t => t.id === p.template_id);
    return template ? (template.regulation || "General") : "Custom";
  };
  const policies = state.policies || [];
  const enabled = policies.filter(p => p.enabled).length;
  const fromTemplates = policies.filter(p => p.template_id).length;
  const critical = policies.filter(p => String(p.severity).toLowerCase() === "critical").length;

  box.append(pageHeader("policies", COMPLIANCE_COPY.policies.header, storeAdmin() ? h("button", {class: "btn primary", onclick: () => policyModal()}, icon("plus"), "New policy") : ""));
  box.append(pageIntro("policies", {
    facts: [
      ["Policies", number(policies.length), policies.length ? `${number(enabled)} enabled` : ""],
      ["From templates", number(fromTemplates), policies.length ? `${number(policies.length - fromTemplates)} custom` : ""],
      ["Critical", number(critical), "highest severity"],
    ],
    actions: [
      introAction("Rule templates", "layers", () => goTo("templates")),
      introAction("Frameworks behind them", "check", () => goTo("frameworks")),
      introAction("Findings they evaluate", "alert", () => goTo("findings")),
    ],
  }));
  if (state.policiesError) {
    box.append(panel("Configured policies", unavailableState(state.policiesError,
      "Policies are read through the admin API.")));
    box.append(await cryptoGateRulesPanel());
    box.append(cryptoPoliciesPanel());
    return box;
  }

  // Filters travel in the link, so "GDPR policies on customer-360" is a URL.
  const search = textInput(param("q"), {placeholder: "Search policies, actions", "aria-label": "Search policies"});
  const origin = selectInput([["", "All origins"], ...optionSet(policies.map(originOf))], param("origin"), {ariaLabel: "Origin"});
  const scope = selectInput([["", "All stores"], ["global", "Global only"], ...state.stores.map(s => [s.store_id, s.store_id])], param("store"), {ariaLabel: "Store"});
  const status = selectInput([["", "Enabled and disabled"], ["on", "Enabled"], ["off", "Disabled"]], param("enabled"), {ariaLabel: "Enabled"});
  const count = h("span", {class: "result-count", role: "status"}, "");
  const list = h("div", {});

  function draw() {
    const rows = policies.filter(p => {
      if (origin.value && originOf(p) !== origin.value) return false;
      if (scope.value === "global" && p.scope_store) return false;
      if (scope.value && scope.value !== "global" && p.scope_store !== scope.value) return false;
      if (status.value === "on" && !p.enabled) return false;
      if (status.value === "off" && p.enabled) return false;
      return fuzzyMatch([p.name, p.description, p.action, p.severity, originOf(p), scopeText(p)].filter(Boolean).join(" "), search.value);
    });
    count.textContent = `${number(rows.length)} of ${number(policies.length)} policies`;
    list.replaceChildren(policies.length && !rows.length
      ? emptyState("No policies match these filters.")
      : table(["Enabled", "Policy", "Origin", "Scope", "Action", "Severity", ""], rows.map(p => {
          const toggle = h("input", {type: "checkbox", checked: p.enabled,
                                     disabled: !can("admin"), title: can("admin") ? null : roleNeed("admin"),
                                     "aria-label": `Enable policy ${p.name}`, onchange: async e => {
            await api(`/admin/policies/${encodeURIComponent(p.id)}`, {method: "PATCH", body: JSON.stringify({enabled: e.target.checked})});
            p.enabled = e.target.checked;
            toast("Policy updated.");
          }});
          return h("tr", {}, h("td", {}, hitBox(toggle)), h("td", {}, h("div", {class: "strong"}, p.name), h("div", {class: "sub"}, p.description)), h("td", {}, originOf(p)), h("td", {}, scopeText(p)),
            // The action in words, with its id under it for configuration.
            h("td", {}, p.action ? [h("div", {}, humanize(p.action)), h("div", {class: "sub mono"}, p.action)] : "-"),
            h("td", {}, badge(p.severity)),
            h("td", {}, rowActions(
              h("button", {class: "btn small", type: "button", onclick: () => policyMatchesModal(p)}, icon("alert"), "Matches"),
              [can("admin") ? {label: "Delete policy", glyph: "trash", danger: true, onclick: () => deletePolicy(p)} : null])));
        }), {tableClass: "policies-table"}));
  }
  const filters = {q: search, origin, store: scope, enabled: status};
  for (const [name, input] of Object.entries(filters)) {
    input.addEventListener(input.tagName === "SELECT" ? "change" : "input", () => {
      setParams({[name]: input.value});
      draw();
    });
  }
  draw();
  box.append(panel("Configured policies", h("div", {},
    toolbar("Filter policies", [
      h("div", {class: "search-field"}, icon("search"), search),
      origin, scope, status, count], {className: "findings-tools tools-above"}),
    list)));
  box.append(await cryptoGateRulesPanel());
  box.append(cryptoPoliciesPanel());
  return box;
}

// The crypto posture policies are built in: every posture audit evaluates
// them beside the network, authentication and CVE rules, so they are listed
// here rather than configured. Each names the state that triggers it, and the
// state that never can.
function cryptoPoliciesPanel() {
  return panel("Built-in crypto posture policies", h("div", {},
    h("p", {class: "sub fw-lede"},
      "Evaluated on every posture audit; they are not configured here. A property the " +
      "store does not expose is not observable, and no policy fires on it."),
    table(["Policy", "Check", "Fires on", "Never fires on", "Severity"],
      Object.entries(CRYPTO_POLICIES).map(([id, p]) => h("tr", {},
        h("td", {}, h("div", {class: "mono strong"}, id), h("div", {class: "sub"}, p.when)),
        h("td", {}, checkLabel(p.check)),
        h("td", {}, cryptoChip("observed_exposure", "failed")),
        h("td", {}, cryptoBadge("not_observable")),
        h("td", {}, badge(p.severity)))))));
}

// The findings a policy fires on, from the recent archive, each opening into
// its detail. The denominator is stated: this is a sample, not the backlog.
async function policyMatchesModal(policy) {
  const body = h("div", {}, loadingState("Reading recent findings"));
  modal(`Findings matched by “${policy.name}”`, body, null, "Close");
  try {
    const findings = await recentFindings(200);
    const matches = findings.filter(f => findingMatchesRule(f, policy.when || {}) &&
      policyAppliesToStore(policy, f) && (!policy.scope_collection || policy.scope_collection === f.collection));
    body.replaceChildren(
      h("p", {class: "sub"}, `${ruleSummary(policy.when || {})} · scope ${scopeText(policy)} · ` +
        `${number(matches.length)} of ${number(findings.length)} recent findings match.`),
      matches.length ? compactFindingsTable(matches, policy.scope_store || "")
                     : statusLine("No recent finding matches this policy.", "info"));
  } catch (e) {
    body.replaceChildren(errorState(unavailableReason(e), null));
  }
}

async function deletePolicy(p) {
  const ok = await confirmAction({
    title: `Delete policy "${p.name || p.id}"?`,
    message: `Findings stop needing action under this rule (${ruleSummary(p.when || {})}, ` +
             `scope ${scopeText(p)}). Disabling it instead keeps the rule for later.`,
    confirmLabel: "Delete policy", danger: true,
  });
  if (!ok) return;
  try {
    await api(`/admin/policies/${encodeURIComponent(p.id)}`, {method: "DELETE"});
    toast("Policy deleted.");
    route();
  } catch (e) { toast(e.message, "err"); }
}

function scopeText(p) {
  return p.scope_store ? `${p.scope_store}${p.scope_collection ? ` / ${p.scope_collection}` : ""}` : "Global / All stores";
}

function policyModal(templateId = "") {
  const template = selectInput([["", "Custom policy"], ...state.templates.map(t => [t.id, `${t.regulation}: ${t.name}`])], templateId);
  const name = textInput("", {placeholder: "Policy name"});
  const action = textInput("", {placeholder: "action_id"});
  const severity = selectInput(severityOrder.map(s => [s, s]), "high");
  const scopeStore = selectInput([["", "Global / All stores"], ...state.stores.map(s => [s.store_id, s.store_id])]);
  const scopeCollection = collectionControl("Scope collection", "", {placeholder: "optional collection"});
  const when = h("textarea", {}, "{\n  \"min_severity\": \"high\"\n}");
  when.value = "{\n  \"min_severity\": \"high\"\n}";
  const hint = h("div", {class: "sub"}, "");
  function update() {
    const t = state.templates.find(x => x.id === template.value);
    hint.replaceChildren(t ? h("div", {}, h("div", {}, t.description), h("div", {class: "rule-box"}, JSON.stringify(t.when || {}, null, 2))) : "Custom policies require name, action, severity, and JSON rule.");
  }
  template.addEventListener("change", update);
  scopeStore.addEventListener("change", () => syncCollectionControl(scopeStore.value, scopeCollection));
  update();
  syncCollectionControl(scopeStore.value, scopeCollection);
  if (templateId) {
    const t = state.templates.find(x => x.id === templateId);
    if (t) {
      name.value = t.name || "";
      action.value = t.action || "";
      severity.value = t.severity || "high";
      when.value = JSON.stringify(t.when || {}, null, 2);
    }
  }
  modal("New policy", h("div", {},
    h("div", {class: "grid"}, field("Template", template), field("Scope store", scopeStore), scopeCollection.field),
    hint,
    h("div", {class: "grid"}, field("Name", name), field("Action", action), field("Severity", severity)),
    field("When rule JSON", when)),
    async () => {
      const payload = {scope_store: scopeStore.value || null, scope_collection: scopeCollection.input.value.trim() || null};
      if (template.value) payload.template_id = template.value;
      else Object.assign(payload, {name: name.value.trim(), action: action.value.trim(), severity: severity.value, when: JSON.parse(when.value), description: ""});
      await api("/admin/policies", {method: "POST", body: JSON.stringify(payload)});
      toast("Policy created.");
      closeModal();
      route();
    });
}

async function renderTemplates() {
  await loadCore();
  const box = h("div", {});
  const search = textInput(param("q"), {placeholder: "Search templates, rules, actions", "aria-label": "Search policy templates"});
  const framework = selectInput([["", "All frameworks"], ...optionSet(state.templates.map(t => t.regulation || "General"))], param("framework"), {ariaLabel: "Framework"});
  const category = selectInput([["", "All categories"], ...[...new Set(state.templates.flatMap(templateCategories))].sort().map(c => [c, categoryLabel(c)])], param("category"), {ariaLabel: "Category"});
  const severity = selectInput([["", "All severities"], ...severityOrder.map(s => [s, severityName(s)])], param("severity"), {ariaLabel: "Severity"});
  const label = selectInput([["", "All labels"], ...optionSet(state.templates.map(t => (t.when || {}).requires_label))], param("label"), {ariaLabel: "Label"});
  const count = h("span", {class: "result-count", role: "status"}, "");
  const list = h("div", {class: "templates"});

  function templateText(t) {
    return [t.id, t.name, t.description, t.regulation, t.action, t.severity, t.default_scope, searchableText(t.when || {})].filter(Boolean).join(" ");
  }

  function draw() {
    const rows = state.templates.filter(t => {
      const rule = t.when || {};
      if (framework.value && String(t.regulation || "General") !== framework.value) return false;
      if (category.value && !templateCategories(t).includes(category.value)) return false;
      if (severity.value && String(t.severity) !== severity.value) return false;
      if (label.value && String(rule.requires_label || "") !== label.value) return false;
      return fuzzyMatch(templateText(t), search.value);
    });
    count.textContent = `${number(rows.length)} of ${number(state.templates.length)} templates`;
    list.replaceChildren(...(rows.length ? rows.map(templateCard) : [statusLine("No matching templates.")]));
  }

  // Filters are part of the view, so they travel in the link.
  const templateFilters = {q: search, framework, category, severity, label};
  for (const [name, input] of Object.entries(templateFilters)) {
    input.addEventListener(input.tagName === "SELECT" ? "change" : "input", () => {
      setParams({[name]: input.value});
      draw();
    });
  }
  box.append(pageHeader("templates", "Read a rule, test it on recent findings, then turn it into a policy."));
  const inUse = new Set((state.policies || []).map(p => p.template_id).filter(Boolean));
  box.append(pageIntro("templates", {
    facts: [
      ["Templates", number(state.templates.length)],
      ["Frameworks", number(new Set(state.templates.map(t => t.regulation || "General")).size)],
      ["Categories", number(new Set(state.templates.flatMap(templateCategories)).size)],
      ["In use", number(state.templates.filter(t => inUse.has(t.id)).length), "have a policy"],
    ],
    actions: [
      introAction("Configured policies", "sliders", () => goTo("policies")),
      introAction("What each framework requires", "layers",
                  () => goTo("frameworks", param("framework") ? {framework: param("framework")} : {})),
    ],
  }));
  // The filters sit directly over the cards they narrow, with the mapping
  // caveat that qualifies every card beneath them.
  box.append(toolbar("Filter templates", [
    h("div", {class: "search-field"}, icon("search"), search),
    framework, category, severity, label, count], {className: "findings-tools templates-tools"}));
  box.append(h("p", {class: "mapping-hint templates-hint"}, mappingHint()));
  box.append(list);
  draw();
  return box;
}

// A template is a detection rule. These three helpers keep its regulatory
// framing — citation, applicability, evidential reach — visible next to it, so
// a match is never read from the UI as a compliance conclusion.
function attributionLine(t) {
  const a = t.attribution || {};
  const parts = [a.source_text || t.regulation || "-"];
  if (a.unresolved && a.unresolved.length) parts.push(`source not confirmed: ${a.unresolved.join(", ")}`);
  return parts.join(" · ");
}

// The template's mapping line (C-7): the same neutral component as Frameworks
// and Criteria. A template the server marks reviewed without a review record
// still says it has none.
function templateMapping(t) {
  const a = t.attribution || {};
  const sources = a.sources || [];
  const lifecycle = a.lifecycle || leastLifecycle(sources.map(src => src.lifecycle)) || "draft";
  return mappingStatus({subject: a, lifecycle, sources, legalStatuses: a.legal_statuses || []});
}

function applicabilityNote(t) {
  const pending = Object.entries(t.applicability || {})
    .filter(([, v]) => v === "requires_confirmation").map(([k]) => questionText(k));
  if (!pending.length) return "";
  return h("div", {class: "applicability-note"},
    `Not sure yet whether it applies (${pending.join("; ")}). A match here is an observation, not a legal conclusion.`);
}

function evidenceBlock(t) {
  const e = t.evidence || {};
  return h("div", {},
    h("dl", {class: "kv"},
      h("dt", {}, "Detects"), h("dd", {}, e.detects || "-"),
      h("dt", {}, "Does not establish"), h("dd", {}, e.does_not_establish || "-"),
      h("dt", {}, "Confidence class"), h("dd", {class: "mono"}, e.confidence || "-"),
      h("dt", {}, "Reviewer decision"), h("dd", {}, e.requires_reviewer_decision ? "Required" : "Not required")),
    (e.limitations || []).length
      ? h("ul", {class: "limitations"}, (e.limitations || []).map(x => h("li", {}, x)))
      : "");
}

function sourceBlock(t) {
  const sources = ((t.attribution || {}).sources) || [];
  if (!sources.length) return statusLine("No maintained source record for this template.", "medium");
  return h("div", {}, sources.map(src => h("div", {class: "source-record"},
    h("div", {class: "spread"},
      h("strong", {}, src.section || src.title || src.id),
      h("span", {class: "tag"}, complianceLabel("lifecycle", src.lifecycle || "draft").text)),
    h("p", {class: "muted"}, [src.issuer, src.title, src.edition].filter(Boolean).join(" · ")),
    h("p", {class: "muted"}, src.notes || ""),
    src.url ? h("a", {href: src.url, target: "_blank", rel: "noopener noreferrer"}, src.url) : "",
    h("p", {class: "muted"},
      src.redistributable === false ? "Licensed standard: linked by locator, text not reproduced. " : "",
      src.verified ? "Provision text retrieved and hashed." : "Provision text not retrieved by this build."))));
}

function templateCard(t) {
  const raw = JSON.stringify(t, null, 2);
  return h("article", {class: "template-card"},
    h("div", {class: "spread"}, h("h3", {}, t.name), badge(t.severity)),
    h("p", {class: "muted"}, t.description || ""),
    h("div", {class: "tag-row"}, h("span", {class: "tag"}, t.regulation || "General"), templateCategories(t).map(c => h("span", {class: "tag"}, categoryLabel(c))), h("span", {class: "tag"}, t.default_scope || "scope optional")),
    h("dl", {class: "kv"},
      h("dt", {}, "Template ID"), h("dd", {class: "mono"}, t.id),
      h("dt", {}, "Source"), h("dd", {}, attributionLine(t), templateMapping(t)),
      h("dt", {}, "Scope"), h("dd", {}, t.default_scope || "-"),
      h("dt", {}, "Action"), h("dd", {}, t.action
        ? [h("div", {}, humanize(t.action)), h("div", {class: "sub mono"}, t.action)] : "-")),
    applicabilityNote(t),
    h("div", {class: "rule-line"}, ruleSummary(t.when || {})),
    h("details", {class: "evidence-data"},
      h("summary", {}, icon("code"), "Rule JSON"),
      h("pre", {class: "rule-box"}, JSON.stringify(t.rule || t.when || {}, null, 2))),
    h("div", {class: "bar"},
      // Not primary: a grid of cards each with a filled button is a wall of
      // equal emphasis. The page header holds the screen's primary action.
      storeAdmin() ? h("button", {class: "btn small", type: "button", onclick: () => customizeTemplateModal(t)}, icon("edit"), "Customize") : "",
      h("button", {class: "btn small", type: "button", onclick: () => inspectTemplateModal(t)}, icon("eye"), "Inspect"),
      h("button", {class: "btn small", type: "button",
                   onclick: () => copyText(raw, "Template JSON")}, icon("copy"), "Copy JSON")));
}

function inspectTemplateModal(t) {
  const body = h("div", {},
    kpiGrid("",
      metric("Framework", t.regulation || "General", (t.attribution || {}).citation || ""),
      metric("Severity", String(t.severity || "info").toUpperCase(), "default"),
      metric("Scope", t.default_scope || "-", "recommended"),
      metric("Action", t.action || "-", "remediation id")),
    h("dl", {class: "kv"},
      h("dt", {}, "Rule"), h("dd", {}, ruleSummary(t.when || {})),
      h("dt", {}, "Category"), h("dd", {}, templateCategories(t).map(categoryLabel).join(", ")),
      h("dt", {}, "Description"), h("dd", {}, t.description || "-")),
    applicabilityNote(t),
    panel("What this rule establishes", evidenceBlock(t)),
    panel("Regulatory source", sourceBlock(t)),
    panel("Rule JSON", jsonBlock(t.when || {})),
    h("div", {id: "template-matches"}, loadingState("Loading recent matching findings")));
  modal(t.name, body, null, "Close");
  loadTemplateMatches(t, body.querySelector("#template-matches"));
}

async function loadTemplateMatches(t, node) {
  try {
    const findings = await recentFindings(60);
    const matches = findings.filter(f => findingMatchesRule(f, t.when || {}));
    node.replaceChildren(panel("Recent matches", h("div", {},
      kpiGrid("",
        metric("Matching findings", number(matches.length), "recent findings sample"),
        metric("Sample size", number(findings.length), "loaded findings")),
      matches.length ? findingsTable(matches) : statusLine("No recent findings matched this template rule."))));
  } catch (e) {
    node.replaceChildren(panel("Recent matches", errorState(e.message)));
  }
}

// The Findings area: observations across recorded assessments, in one place
// rather than buried inside each result panel. The denominator is stated,
// because a filtered count over a capped fetch is otherwise a lie of omission.
// The criteria screen. Four fields, kept apart on purpose: whether the
// obligation applies, what the run observed, whether the evidence is sufficient,
// and what a named person concluded. Collapsing them into one badge is exactly
// the failure this product exists to prevent, so the UI renders them as four
// columns and states which inputs are still missing.

// The labels live in COMPLIANCE_COPY; this name stays for the filters and
// chips that read it. Only a reviewer's "met" reaches the fourth state, and it
// is neutral with a check mark, never green (D-C1).
const CRITERION_STATUS = COMPLIANCE_COPY.labels.criterionStatus;

// Applicability answers and reviewer decisions are stored per store on the
// server now, and evidence states come from recorded reviews. The console no
// longer keeps a what-if copy in the URL: what the screen shows is the record.
const REVIEW_CONCLUSIONS = ["satisfied", "gap", "not_applicable"]
  .map(key => [key, COMPLIANCE_COPY.labels.conclusion[key].text]);

function storeOptions(first = ["", "Choose a store"]) {
  return [first, ...(state.stores || []).map(s => [s.store_id, s.store_id])];
}

// Frameworks. Counts by state, never a percentage: a compliance score would
// average together things that are not comparable, and would let an unanswered
// applicability question quietly improve the number.

// What the pack's identifiers mean, in the words a reader needs. Check names
// come from the orchestrator; artifact and question names from the pack. An
// identifier with no entry is shown as itself, never dropped.
const CHECK_GLOSSARY = {
  data_classification: ["Data classification",
    "Chunk text is scanned for PII, PHI, card numbers, credentials, and secrets."],
  tenant_isolation: ["Tenant isolation",
    "Every chunk's tenant is read; every chunk's own vector is then queried under every other tenant's filter, plus a whole-view query per tenant and a query for a tenant that does not exist. Within the configured query budget this is exhaustive; over it, the check is sampled and partial."],
  configuration_posture: ["Configuration posture",
    "Network exposure, transport encryption, and known CVEs for the store's client and server."],
  network_exposure: ["Network exposure",
    "Whether the store's endpoint resolves to a public address or carries a private-network marker."],
  authentication: ["Store authentication",
    "Whether the store serves data to a caller that presents no credentials."],
  cve: ["Known CVEs",
    "The client library VecShield connects through is checked against published vulnerabilities (OSV) for its installed version. The server binary is not."],
  transport_encryption: ["TLS on VecShield's connection",
    "The protocol of the connection the assessment makes, from the live session where the client exposes it."],
  transport_tls_enforcement: ["Plaintext connections refused",
    "Whether the store refuses a client that does not use TLS. An active probe, off unless requested, never sends credentials over plaintext."],
  tls_certificate_verification: ["TLS certificate verification",
    "Whether VecShield's TLS connection verifies the server certificate. TLS without verification encrypts the channel but does not authenticate the store."],
  at_rest_encryption: ["Database-native encryption at rest",
    "What the database itself reports about encryption at rest. Disk and cloud key management it does not expose are not observable."],
  field_encryption: ["Field-level encryption",
    "Fields the database encrypts client- or server-side, where its interface declares them."],
  data_representation: ["Sensitive data representation",
    "Whether sensitive values are stored masked, tokenised, or as plaintext, and whether a field mixes the two."],
  pan_representation: ["PAN storage representation",
    "Card numbers stored full, truncated, tokenised, or hashed. Counts only; no number is shown."],
  direct_identifier_exposure: ["Direct identifiers beside pseudonymous ones",
    "Direct identifiers stored next to a pseudonymous key that could have replaced them."],
  retrieval_exposure: ["Retrieval-time plaintext exposure",
    "Stored vectors replayed as queries, counting sensitive plaintext the retrieval layer returns. Opt-in and read-only."],
  rag_integrity: ["RAG integrity scan",
    "One pass over a collection for injected instructions, anomalous embeddings, and missing provenance."],
  prompt_injection: ["Prompt-injection detection",
    "Stored chunks and metadata are matched against known instruction-injection patterns."],
  embedding_anomaly: ["Embedding anomaly detection",
    "Vectors far outside their collection's distribution are flagged for review."],
  provenance: ["Provenance coverage",
    "Whether chunks carry source, ingest time, and owner metadata."],
  erasure_verification: ["Erasure verification",
    "After a deletion, the subject is searched for again to confirm nothing still returns."],
  training_data_classification: ["Training-data classification",
    "Upstream datasets are scanned before they are embedded."],
  chunk_boundary: ["Chunk boundary check",
    "Records are checked for sensitive content split across chunk boundaries."],
  access_grants: ["Access grants",
    "The store's own roles and grants on the vector tables, judged for least privilege of the role the retrieval application connects as. A store that reports no grants reads as not observable."],
  embedding_consistency: ["Embedding consistency",
    "Each collection's declared embedding model and vector dimension, checked for contradictions. It detects disagreement, not whether the declared model produced the vectors."],
  retention_horizon: ["Retention horizon",
    "How old the records are, where they carry a date. It reports the age, not whether that age is permitted: VecShield does not hold the retention schedule."],
};

// What each regulation is, for readers who arrive from the security side.
// Descriptive only: citations, issuers, and status come from the pack's own
// source records, and a framework with no profile still renders from those.
const FRAMEWORK_PROFILES = {
  "HIPAA": {
    mark: "HIP", jurisdiction: "United States",
    name: "Health Insurance Portability and Accountability Act — Security Rule",
    appliesTo: "Covered entities and business associates that handle electronic protected health information (ePHI)",
    stake: "Embeddings built from clinical notes, claims, or patient messages are ePHI. Access control, an inventory of where ePHI sits, and audit obligations follow the data into the index.",
  },
  "GDPR": {
    mark: "GDPR", jurisdiction: "European Union and EEA",
    name: "General Data Protection Regulation (EU) 2016/679",
    appliesTo: "Controllers and processors handling personal data of people in the EU, wherever the processing happens",
    stake: "Personal data does not stop being personal data once it is a vector. Erasure must reach the index and its backups, and Art. 32 security measures include isolation between tenants and access control on the store.",
  },
  "CCPA/CPRA": {
    mark: "CCPA", jurisdiction: "California, United States",
    name: "California Consumer Privacy Act, as amended by the California Privacy Rights Act",
    appliesTo: "Businesses above the CCPA thresholds that collect California residents' personal information",
    stake: "A consumer's deletion request has to reach personal information held in embeddings, and the business must be able to show that it did.",
  },
  "PCI-DSS": {
    mark: "PCI", jurisdiction: "Contractual — card brands, via the PCI Security Standards Council",
    name: "Payment Card Industry Data Security Standard",
    appliesTo: "Any entity that stores, processes, or transmits cardholder or sensitive authentication data",
    stake: "Account data should not be retained in a vector store at all. Where it is, the store is inside the cardholder data environment and the data must be rendered unreadable.",
  },
  "SOC 2": {
    mark: "SOC2", jurisdiction: "Attestation standard — United States, used globally",
    name: "AICPA Trust Services Criteria (SOC 2)",
    appliesTo: "Service organisations reporting on security, availability, confidentiality, processing integrity, or privacy controls",
    stake: "Credentials in the embedded data layer are a CC6.1 logical-access failure; injected or anomalous content the retrieval layer serves without detection is a CC7.2 monitoring failure.",
  },
  "EU AI Act": {
    mark: "AI", jurisdiction: "European Union",
    name: "Artificial Intelligence Act (EU) 2024/1689",
    appliesTo: "Providers and deployers of AI systems placed on the EU market, with the heaviest duties on high-risk systems",
    stake: "Art. 10 data governance covers the corpus a retrieval-augmented system draws on: its provenance, its integrity, and its freedom from injected content.",
  },
};

function frameworkProfile(framework) {
  return FRAMEWORK_PROFILES[framework] || {
    mark: String(framework || "?").replace(/[^A-Za-z0-9]/g, "").slice(0, 4).toUpperCase() || "?",
    name: framework, jurisdiction: "", appliesTo: "", stake: "",
  };
}

function frameworkAnchor(framework) {
  return `fw-${String(framework).toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
}

function groupByFramework(criteria) {
  const byFramework = new Map();
  for (const criterion of criteria || []) {
    const list = byFramework.get(criterion.framework) || [];
    list.push(criterion);
    byFramework.set(criterion.framework, list);
  }
  return new Map([...byFramework.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

function distinct(criteria, key) {
  return [...new Set((criteria || []).flatMap(c => c[key] || []))];
}

// The sources behind a framework's criteria, de-duplicated by locator.
function frameworkSources(criteria) {
  const seen = new Map();
  for (const c of criteria || []) {
    for (const src of c.sources || []) {
      const key = src.id || src.section || src.title || JSON.stringify(src);
      if (!seen.has(key)) seen.set(key, src);
    }
  }
  return [...seen.values()];
}

function checkLabel(name) {
  return (CHECK_GLOSSARY[name] || [CATEGORY_LABELS[name] || String(name).replace(/_/g, " ")])[0];
}

async function renderFrameworks() {
  await loadCore();
  const box = h("div", {class: "criteria-page"});
  box.append(pageHeader("frameworks", COMPLIANCE_COPY.frameworks.header));
  const out = h("div", {});
  box.append(out);
  out.replaceChildren(loadingState("Loading the criterion pack"));
  try {
    const pack = await loadPack();
    // Best-effort: the boundary panel is worth showing when it is available
    // and not worth failing the page over when it is not.
    let hipaa = null;
    try { hipaa = await api("/compliance/hipaa"); } catch (e) { hipaa = null; }
    // Same rule for the encryption basis: one table the Crypto screen, these
    // cards and the plan all follow, shown when served and never guessed at.
    let basis = [];
    try { basis = (await api("/compliance/crypto-basis")).basis || []; } catch (e) { basis = []; }
    const cryptoBasis = new Map((Array.isArray(basis) ? basis : []).map(row => [row.framework, row]));
    const groups = groupByFramework(pack.criteria || []);
    const checks = distinct(pack.criteria, "technical_checks");
    const artifacts = distinct(pack.criteria, "manual_evidence");
    const focus = groups.has(param("framework")) ? param("framework") : "";

    out.replaceChildren(
      pageIntro("frameworks", {
        facts: [
          ["Frameworks", number(groups.size)],
          ["Criteria", number((pack.criteria || []).length)],
          ["Automated checks", number(checks.length), "distinct"],
          ["Documents to supply", number(artifacts.length), "distinct"],
        ],
        actions: [
          introAction("See where a store stands", "check",
                      () => goTo("criteria", focus ? {framework: focus} : {}), true),
          introAction("Rule templates", "layers", () => goTo("templates")),
          introAction("Configured policies", "sliders", () => goTo("policies")),
        ],
      }),
      panel("This pack", h("div", {},
        h("dl", {class: "kv"},
          h("dt", {}, "Version"), h("dd", {class: "mono"}, pack.pack.pack_version),
          h("dt", {}, "Criteria"), h("dd", {}, number(pack.pack.criteria)),
          h("dt", {}, "Mapping"), h("dd", {}, mappingStatus({pack: pack.pack, hint: true,
            lifecycle: leastLifecycle((pack.criteria || []).map(c => c.lifecycle).concat(pack.pack.lifecycle || []))}))),
        statusLine(pack.pack.note || "", "medium"))),
      panel("Frameworks at a glance",
        h("div", {},
          h("p", {class: "sub fw-lede"}, COMPLIANCE_COPY.frameworks.barLede),
          h("div", {class: "fw-grid"},
            [...groups.entries()].map(([framework, criteria]) =>
              frameworkCard(framework, criteria, framework === focus,
                            cryptoBasis.get(framework)))))),
      panel("What the assessment observes, by framework",
        checkMatrix(groups, checks)),
      notCoveredPanel(hipaa),
      ...[...groups.entries()].map(([framework, criteria]) =>
        frameworkSection(framework, criteria, framework === focus,
                         cryptoBasis.get(framework))));

    // The section is not in the document until route() mounts it.
    if (focus) {
      setTimeout(() => document.getElementById(frameworkAnchor(focus))
        ?.scrollIntoView?.({block: "start", behavior: "smooth"}), 0);
    }
  } catch (e) {
    out.replaceChildren(panel("Frameworks", unavailableState(unavailableReason(e),
      "The criterion pack is served by the compliance API.")));
  }
  return box;
}

// Obligations the pack names and then declines to assess.
//
// This is deliberately given the same visual weight as the coverage panels
// above it. A coverage matrix that only lists what a tool does is the normal
// thing to ship and the easy thing to read as completeness; the boundary is
// the part a reader cannot reconstruct for themselves, and it is the honest
// answer to "so does this cover HIPAA". Each row names the provision, so a
// reader can check that the reason given is about the product's reach rather
// than about the obligation being unimportant.
function notCoveredPanel(hipaa) {
  const rows = hipaa?.pack?.not_covered || [];
  if (!rows.length) return "";
  return panel("What this pack does not reach", h("div", {},
    h("p", {class: "sub fw-lede"},
      "These HIPAA obligations are real and this pack does not assess them. " +
      "They are listed because a coverage map that omits its own boundary " +
      "reads as completeness, and because an assessor will ask."),
    table(["Obligation", "Provision", "Why it is out of reach"], rows.map(row => h("tr", {},
      h("td", {}, row.topic || ""),
      h("td", {class: "mono nowrap"}, row.section || ""),
      h("td", {class: "sub"}, row.reason || ""))), {tableClass: "tbl"}),
    statusLine(
      "Absence from this list is not coverage: it means the obligation is " +
      "assessed by a criterion above, not that it is met.", "medium")));
}

// One regulation, summarised. The bar is proportional to counts and labelled
// with them; it carries no percentage anywhere a reader could mistake for a score.
function frameworkCard(framework, criteria, focused, basisRow = null) {
  const profile = frameworkProfile(framework);
  const checks = distinct(criteria, "technical_checks");
  const artifacts = distinct(criteria, "manual_evidence");
  const sources = frameworkSources(criteria);
  const issuer = sources.find(src => src.issuer)?.issuer || profile.jurisdiction || "";
  return h("article", {class: `fw-card${focused ? " fw-focus" : ""}`},
    h("div", {class: "fw-card-head"},
      h("span", {class: "fw-mark", "aria-hidden": "true"}, profile.mark),
      h("div", {class: "fw-card-title"},
        h("h3", {}, framework),
        h("div", {class: "sub fw-inst"}, issuer))),
    mixBar(checks.length, artifacts.length,
           `${framework}: ${countText(checks.length, COMPLIANCE_COPY.frameworks.barAuto)}, ${countText(artifacts.length, COMPLIANCE_COPY.frameworks.barManual)}`),
    h("dl", {class: "fw-counts"},
      h("div", {}, h("dt", {}, "Criteria"), h("dd", {}, number(criteria.length))),
      h("div", {}, h("dt", {}, "Automated"), h("dd", {}, number(checks.length))),
      h("div", {}, h("dt", {}, "Documents"), h("dd", {}, number(artifacts.length)))),
    basisRow
      ? h("div", {class: "fw-crypto-line"},
          h("span", {class: "metric-k"}, icon("lock"), "Encryption"),
          relationshipTag(basisRow))
      : "",
    h("div", {class: "bar"},
      h("button", {class: "btn small", type: "button",
                   onclick: () => {
                     setParams({framework});
                     document.getElementById(frameworkAnchor(framework))
                       ?.scrollIntoView?.({block: "start", behavior: "smooth"});
                   }},
        icon("layers"), "Obligations"),
      h("button", {class: "btn small", type: "button",
                   onclick: () => goTo("criteria", {framework})},
        icon("check"), "See a store")));
}

// Two segments, automated against manual. Drawn in SVG so the widths are
// attributes, not inline styles the CSP forbids.
function mixBar(automated, manual, label) {
  const total = Math.max(1, automated + manual);
  const width = 100, height = 8;
  const autoW = (automated / total) * width;
  return h("figure", {class: "mix"},
    h("svg", {class: "mix-svg", viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: "none",
              role: "img", "aria-label": label},
      h("title", {}, label),
      h("rect", {x: "0", y: "0", width: String(width), height: String(height), rx: "4",
                 fill: "var(--surface-3)"}),
      automated
        ? h("rect", {x: "0", y: "0", width: String(Math.max(2, autoW)), height: String(height),
                     rx: "4", fill: "var(--accent)"})
        : "",
      manual
        ? h("rect", {x: String(autoW), y: "0", width: String(Math.max(2, width - autoW)),
                     height: String(height), rx: "4", fill: "var(--medium)"})
        : ""),
    h("figcaption", {class: "mix-legend"},
      h("span", {class: "mix-key mix-key-auto"}, countText(automated, COMPLIANCE_COPY.frameworks.barAuto)),
      h("span", {class: "mix-key mix-key-manual"}, countText(manual, COMPLIANCE_COPY.frameworks.barManual))));
}

// Which automated check informs which framework. A dot is "at least one
// criterion of this framework is informed by this check"; nothing about
// whether it passed, which is the Criteria screen's job.
function checkMatrix(groups, checks) {
  const frameworks = [...groups.keys()];
  const order = Object.keys(CHECK_GLOSSARY);
  const rows = [...checks].sort((a, b) => {
    const ia = order.indexOf(a), ib = order.indexOf(b);
    return (ia === -1 ? order.length : ia) - (ib === -1 ? order.length : ib) || a.localeCompare(b);
  });
  if (!rows.length) return emptyState("No criterion in this pack names an automated check.");
  const uses = new Map(frameworks.map(f => [f, new Set(distinct(groups.get(f), "technical_checks"))]));
  return h("div", {},
    h("p", {class: "sub fw-lede"},
      "A dot means at least one of the framework's criteria is informed by that check. " +
      "Whether the check ran, and what it found, is on the Criteria screen for a store."),
    // A framework's column head is its mark, named for a screen reader; the
    // same name labels the column's cells below 900px, where a row is a card.
    table(["Automated check", ...frameworks.map(f => ({
      className: "matrix-col", srLabel: f,
      label: [h("span", {class: "fw-mark fw-mark-sm", "aria-hidden": "true"}, frameworkProfile(f).mark),
              h("span", {class: "sr-only"}, f)]}))],
      rows.map(check => h("tr", {},
        h("th", {scope: "row"},
          h("div", {class: "strong"}, checkLabel(check)),
          // The description, or the check's id when there is none; never
          // the id again under a label that is the id ("cve / cve").
          (CHECK_GLOSSARY[check] || [])[1]
            ? h("div", {class: "sub"}, CHECK_GLOSSARY[check][1])
            : checkLabel(check) !== check ? h("div", {class: "sub mono"}, check) : ""),
        frameworks.map(f => {
          const on = uses.get(f).has(check);
          return h("td", {class: "matrix-cell"},
            h("span", {class: `dot${on ? " dot-on" : ""}`, "aria-hidden": "true"}),
            h("span", {class: "sr-only"}, on ? `used by ${f}` : `not used by ${f}`));
        }))), {tableClass: "matrix"}));
}

function frameworkSection(framework, criteria, focused, basisRow = null) {
  const profile = frameworkProfile(framework);
  const sources = frameworkSources(criteria);
  const primary = sources[0] || {};
  const status = sources.map(src => src.status).find(Boolean);
  const effective = sources.map(src => src.application_date || src.effective_date).find(Boolean);
  const kinds = [...new Set(sources.map(src => src.kind).filter(Boolean))];

  // The framework's name is the section's heading; its criteria are h3s.
  const headingId = `${frameworkAnchor(framework)}-title`;
  return panel([h("span", {class: "fw-mark fw-mark-sm", "aria-hidden": "true"}, profile.mark), " ", framework],
    [
      mappingStatus({lifecycle: leastLifecycle(criteria.map(c => c.lifecycle).concat(state.pack?.pack?.lifecycle || [])),
                     pack: state.pack?.pack, sources}),
      h("div", {class: "fw-profile"},
        h("div", {class: "fw-profile-text"},
          h("div", {class: "fw-profile-name"}, profile.name || primary.title || framework),
          profile.stake ? h("p", {class: "muted"}, profile.stake) : ""),
        h("dl", {class: "kv fw-kv"},
          primary.issuer ? [h("dt", {}, "Issuer"), h("dd", {}, primary.issuer)] : "",
          profile.jurisdiction ? [h("dt", {}, "Jurisdiction"), h("dd", {}, profile.jurisdiction)] : "",
          profile.appliesTo ? [h("dt", {}, "Applies to"), h("dd", {}, profile.appliesTo)] : "",
          kinds.length ? [h("dt", {}, "Instrument"), h("dd", {}, kinds.map(k => complianceLabel("sourceKind", k).text).join(", "))] : "",
          status ? [h("dt", {}, "Status"),
                    h("dd", {}, complianceLabel("legalStatus", status).text, effective ? ` · applies from ${effective}` : "")] : "",
          [h("dt", {}, "Cited"), h("dd", {}, sources.length
            ? h("div", {class: "tag-row"}, sources.map(src => sourceTag(src)))
            : h("span", {class: "sub"}, "no maintained source record"))])),
      cryptoBasisBlock(framework, basisRow),
      h("div", {class: "crit-list"}, criteria.map(c => criterionSpec(c))),
      h("div", {class: "bar"},
        h("button", {class: "btn small primary", type: "button",
                     onclick: () => goTo("criteria", {framework})},
          icon("check"), `See where a store stands on ${framework}`),
        h("button", {class: "btn small", type: "button",
                     onclick: () => goTo("templates", {framework})},
          icon("layers"), `${framework} templates`),
        h("button", {class: "btn small", type: "button",
                     onclick: () => goTo("policies", {origin: framework})},
          icon("sliders"), `${framework} policies`))],
    h("span", {class: "sub"}, countText(criteria.length, COMPLIANCE_COPY.questionnaire.criteria)),
    {id: frameworkAnchor(framework), headingId, className: `fw-section${focused ? " fw-focus" : ""}`});
}

// What this regulation says about encryption, and how strongly VecShield may
// lean on it. The relationship label is the ceiling for every criterion below:
// a supporting-only framework has no encryption criterion at all.
function cryptoBasisBlock(framework, row) {
  if (!row) return "";
  const supporting = row.relationship === "supporting";
  return h("div", {class: `fw-crypto${supporting ? " fw-crypto-supporting" : ""}`,
                   dataset: {framework}},
    h("div", {class: "fw-crypto-head"},
      h("span", {class: "fw-crypto-title"}, icon("lock"), "Cryptographic protection"),
      relationshipTag(row)),
    h("dl", {class: "kv fw-kv"},
      h("dt", {}, "At rest"), h("dd", {}, row.at_rest || "-"),
      h("dt", {}, "In transit"), h("dd", {}, row.in_transit || "-"),
      h("dt", {}, "Reading"), h("dd", {}, row.interpretation || "-"),
      row.applicability ? [h("dt", {}, "Applies to"), h("dd", {}, row.applicability)] : ""),
    supporting
      ? statusLine(`${row.relationship_label || "Supporting evidence only"} — no encryption ` +
                   "mandate. No criterion evaluates encryption for this framework.", "info")
      : "",
    h("div", {class: "bar"},
      h("button", {class: "btn small", type: "button", onclick: () => goTo("crypto")},
        icon("lock"), "Open the Crypto view"),
      (row.criteria || []).length
        ? h("span", {class: "sub"}, `Evaluated by ${row.criteria.join(", ")}`)
        : ""));
}

function sourceTag(src) {
  const text = src.section || src.title || src.id || "source";
  const title = [src.title, src.edition].filter(Boolean).join(" · ");
  return src.url
    ? h("a", {class: "tag tag-link", href: src.url, target: "_blank", rel: "noopener noreferrer", title}, text)
    : h("span", {class: "tag", title}, text);
}

// One obligation in full: what it says, where it comes from, what the run can
// observe for it, what a person must supply, and when it applies at all.
function criterionSpec(c) {
  const checks = c.technical_checks || [];
  const artifacts = c.manual_evidence || [];
  const fallback = c.fallback_evidence || [];
  const questions = c.applicability_questions || [];
  const limits = c.limitations || [];
  return h("article", {class: "crit"},
    h("div", {class: "crit-head"},
      h("div", {class: "crit-title"},
        h("h3", {class: "crit-name"}, criterionTitle(c)),
        h("p", {class: "crit-obligation"}, c.paraphrase),
        h("div", {class: "crit-id"}, c.criterion_id)),
      h("div", {class: "crit-cite"},
        (c.sources || []).length
          ? (c.sources || []).map(src => sourceTag(src))
          : h("span", {class: "sub"}, "no source record"),
        mappingStatus({subject: c, pack: state.pack?.pack, sources: c.sources}))),
    h("div", {class: "crit-cols"},
      critColumn("Checked automatically", "shield", checks.length
        ? checks.map(name => critItem(checkLabel(name), (CHECK_GLOSSARY[name] || [])[1] || ""))
        : [h("li", {class: "sub"}, COMPLIANCE_COPY.criteria.specNothing)]),
      critColumn("Documents you must supply", "file", artifacts.length || fallback.length
        ? [...artifacts.map(name => critItem(evidenceName(name), evidenceInfo(name).what)),
           ...fallback.map(name => critItem(`${evidenceName(name)} (conditional)`,
             `Only when the checks can't show this through the store. ${evidenceInfo(name).what}`.trim()))]
        : [h("li", {class: "sub"}, "None: the automatic checks cover it")]),
      critColumn(COMPLIANCE_COPY.criteria.specNotAsked, "user", questions.length
        ? questions.map(q => critItem(questionText(q), ""))
        : [h("li", {class: "sub"}, COMPLIANCE_COPY.criteria.specNoQuestions)])),
    limits.length || c.interpretation_notes
      ? h("details", {class: "evidence-data"},
          h("summary", {}, icon("info"), "Limits of these checks"),
          limits.length ? h("ul", {class: "limitations"}, limits.map(l => h("li", {}, l))) : "",
          c.interpretation_notes ? h("p", {class: "crit-note"}, c.interpretation_notes) : "")
      : "");
}

function critColumn(title, glyph, items) {
  return h("div", {class: "crit-col"},
    h("div", {class: "crit-col-title"}, icon(glyph), title),
    h("ul", {class: "crit-items"}, items));
}

function critItem(name, note) {
  return h("li", {},
    h("span", {class: "strong"}, name),
    note ? h("span", {class: "sub"}, note) : "");
}

// Evidence: what exists, and separately, what it was judged to prove.
//
// Two records the screen keeps apart on purpose. An *artifact* is a document
// someone registered; its state says whether the file can be relied on. An
// *evidence review* is a named reviewer's decision that one artifact does or
// does not satisfy one requirement of one criterion, for a scope and period.
async function renderEvidence() {
  await loadCore();
  const box = h("div", {class: "evidence-page"});
  box.append(pageHeader("evidence",
    "Documents you add, and what a reviewer decided each one shows.",
    gated("compliance", h("button", {class: "btn primary", type: "button", onclick: () => registerEvidenceModal()},
      icon("plus"), "Add document"))));
  const out = h("div", {});
  box.append(out);
  out.replaceChildren(loadingState("Loading evidence"));
  try {
    const [artifacts, reviews] = await Promise.all([
      api("/compliance/evidence"), api("/compliance/reviews"),
    ]);
    // The pack explains requirements and names criteria. Best-effort: the
    // register is still worth showing without it.
    let pack = null;
    try { pack = await loadPack(); } catch (e) { pack = null; }
    const lifecycle = artifacts.lifecycle || null;
    const fallbackFor = new Map((pack?.criteria || []).map(c =>
      [c.criterion_id, new Set(c.fallback_evidence || [])]));
    const reviewsByArtifact = new Map();
    for (const review of reviews.reviews || []) {
      const list = reviewsByArtifact.get(review.artifact_id) || [];
      list.push(review);
      reviewsByArtifact.set(review.artifact_id, list);
    }
    const items = artifacts.artifacts || [];
    const reviewed = reviews.reviews || [];
    const byId = new Map(items.map(a => [a.id, a]));
    const usable = items.filter(a => a.usable).length;
    const accepted = reviewed.filter(r => r.accepted).length;
    const stale = reviewed.filter(r => r.accepted &&
      items.some(a => a.id === r.artifact_id && !a.usable)).length;
    const ctx = {lifecycle, byId, reviewsByArtifact, fallbackFor, items};

    const tab = ["artifacts", "reviews", "supply"].includes(param("tab")) ? param("tab") : "artifacts";
    const panels = {
      artifacts: artifactsPanel(ctx),
      reviews: reviewsPanel(reviewed, ctx),
      supply: pack ? evidenceRequirementsPanel(pack) : panel("Documents the pack asks for",
        unavailableState("The criterion pack could not be read."), null,
        {className: "ev-panel", dataset: {tab: "supply"}}),
    };
    // The three records swap in place under one tab panel, so they are tabs
    // (every tab stays in the Tab order on a page), not a toggle group.
    const tabs = tabList({id: "evidence", label: "Evidence records", className: "tabs ev-tabs", current: tab,
      dataKey: "tab", panelClass: "ev-tabpanel", onSelect: key => show(key),
      tabs: [["artifacts", "Documents", number(items.length)], ["reviews", "Reviews", number(reviewed.length)],
             ["supply", "What to supply"]]});
    tabs.panel.append(...Object.values(panels));
    function show(key) {
      for (const [name, node] of Object.entries(panels)) if (node && node.hidden !== undefined) node.hidden = name !== key;
      setParams({tab: key === "artifacts" ? "" : key});
    }
    out.replaceChildren(
      pageIntro("evidence", {
        facts: [
          ["Documents", number(items.length), items.length ? `${number(usable)} ready for review` : ""],
          ["Reviews", number(reviewed.length),
           reviewed.length ? `${number(accepted)} accepted · ${number(reviewed.length - accepted)} not accepted` : ""],
          ["Acceptances that no longer count", number(stale), stale ? "document no longer usable" : ""],
          ["Unreviewed", number(items.filter(a => !reviewsByArtifact.has(a.id)).length),
           "not judged against anything"],
        ],
        actions: [
          introAction("Add documents from a criterion", "check", () => goTo("criteria")),
          introAction("What each criterion requires", "layers", () => goTo("frameworks")),
        ],
      }),
      evidenceExplainer(pack),
      tabs.bar,
      tabs.panel);
    show(tab);
  } catch (e) {
    out.replaceChildren(panel("Evidence", e.status === 409
      ? unavailableState(unavailableReason(e), "Evidence is stored with scan history.")
      : errorState(unavailableReason(e), () => route())));
  }
  return box;
}

// Always visible: the two records, why one file can be judged two ways, what
// superseded means, and what a reviewer checks.
function evidenceExplainer(pack) {
  const checks = pack?.reviewer_checklist || [];
  return h("section", {class: "ev-explain", "aria-label": "Documents and reviews"},
    h("div", {class: "ev-explain-grid"},
      h("div", {class: "ev-explain-card"},
        h("h2", {class: "ev-explain-k"}, icon("file"), termUse("document")),
        h("p", {}, COMPLIANCE_TERMS.document[1], " For example a policy, a business associate agreement, a record of " +
          "processing, an access review, or a penetration-test report. The file stays in your storage."),
        h("p", {class: "sub"}, "Its state says whether the file can be relied on. It shows nothing by itself.")),
      h("div", {class: "ev-explain-card"},
        h("h2", {class: "ev-explain-k"}, icon("check"), "Review"),
        h("p", {}, "A named reviewer's decision, with a reason, that one document does or does not meet one " +
          "need of one criterion, for a store and period."),
        h("p", {class: "sub"}, "Only accepted reviews of documents that are ready for review count toward a criterion."))),
    h("p", {class: "ev-explain-note"},
      h("span", {class: "strong"}, "One file, several decisions. "),
      "A BAA that names the retrieval corpus can be accepted as the vendor contract for one criterion " +
      "and rejected as the risk analysis for another, because it is a different kind of document. " +
      "A policy covering January to June is rejected for a Q3 review."),
    h("p", {class: "ev-explain-note"},
      h("span", {class: "strong"}, "Replaced "),
      "means a newer version was added to replace this one. Acceptances that rested on the old " +
      "version stop counting until the new one is reviewed; expired and withdrawn documents stop counting the same way."),
    checks.length
      ? h("details", {class: "ev-checks"},
          h("summary", {}, icon("info"), "What a reviewer checks before accepting"),
          h("ol", {}, checks.map(item => h("li", {}, item))))
      : "");
}

// A button that shows a lifecycle move in words, from COMPLIANCE_COPY.
const ARTIFACT_MOVES = Object.fromEntries(Object.entries(COMPLIANCE_COPY.labels.artifactMove)
  .map(([key, meta]) => [key, [meta.text, meta.help]]));

function artifactsPanel(ctx) {
  const {items} = ctx;
  const search = textInput(param("aq"), {type: "search", placeholder: "Search title, id or note",
                                         "aria-label": "Search documents"});
  const states = [...new Set(items.map(a => a.state).filter(Boolean))].sort();
  const stateSel = selectInput([["", "Any state"], ...states.map(s => [s, complianceLabel("artifactState", s).text])],
                               param("astate"), {"aria-label": "Document state"});
  const scopes = [...new Set(items.map(a => a.scope || ""))].sort();
  const scopeSel = selectInput([["", "Any store"], ...scopes.map(s => [s || "__estate__", s || "Estate-wide"])],
                               param("ascope"), {"aria-label": "Store"});
  const count = h("span", {class: "result-count", role: "status"}, "");
  const list = h("div", {class: "ev-rows"});
  function draw() {
    const q = search.value.trim().toLowerCase();
    const shown = items.filter(a =>
      (!stateSel.value || a.state === stateSel.value) &&
      (!scopeSel.value || (a.scope || "__estate__") === scopeSel.value) &&
      (!q || [a.title, a.id, a.note].some(t => String(t || "").toLowerCase().includes(q))));
    count.textContent = `${number(shown.length)} of ${number(items.length)}`;
    const open = param("artifact");
    list.replaceChildren(...(shown.length
      ? shown.map(a => artifactRow(a, ctx, a.id === open))
      : [emptyState(items.length ? "No document matches these filters." : "No document has been added yet.",
          items.length || !can("compliance") ? {} : {action: () => registerEvidenceModal(), actionLabel: "Add document"})]));
  }
  for (const control of [search, stateSel, scopeSel]) {
    control.addEventListener(control === search ? "input" : "change", () => {
      setParams({aq: search.value.trim(), astate: stateSel.value, ascope: scopeSel.value});
      draw();
    });
  }
  draw();
  return panel("Documents", [
    h("div", {class: "ev-tools", role: "search", "aria-label": "Filter documents"}, search, stateSel, scopeSel, count),
    list], null, {className: "ev-panel", dataset: {tab: "artifacts"}});
}

function artifactRow(a, ctx, open) {
  const reviews = ctx.reviewsByArtifact.get(a.id) || [];
  const anchor = `ev-${String(a.id).replace(/[^A-Za-z0-9_-]/g, "-")}`;
  const detail = h("div", {class: "ev-detail", id: `${anchor}-detail`, hidden: !open}, artifactDetail(a, ctx));
  const head = h("button", {class: "ev-row-head", type: "button", "aria-expanded": String(open),
                            "aria-controls": `${anchor}-detail`, onclick: toggle},
    h("span", {class: "ev-row-main"},
      h("span", {class: "strong"}, a.title),
      h("span", {class: "sub mono"}, a.id)),
    h("span", {class: "ev-row-state"}, artifactState(a)),
    h("span", {class: "ev-row-scope"},
      h("span", {}, a.scope || "unscoped"),
      h("span", {class: "sub"}, a.period_start || a.period_end
        ? `${a.period_start || "…"} → ${a.period_end || "…"}`
        : "no period stated — it evidences no particular window")),
    h("span", {class: "ev-row-judged"}, evidenceJudgement(reviews, a)),
    h("span", {class: "crit-row-chev", "aria-hidden": "true"}));
  const row = h("article", {class: `ev-row${open ? " is-open" : ""}`, id: anchor, dataset: {artifact: a.id}},
    h("h3", {class: "ev-row-h"}, head), detail);
  function toggle() {
    const opening = head.getAttribute("aria-expanded") !== "true";
    for (const other of row.parentNode?.children || []) {
      if (other === row || !other.classList?.contains("ev-row")) continue;
      other.classList.remove("is-open");
      other.querySelector?.(".ev-row-head")?.setAttribute("aria-expanded", "false");
      const d = other.querySelector?.(".ev-detail");
      if (d) d.hidden = true;
    }
    head.setAttribute("aria-expanded", String(opening));
    detail.hidden = !opening;
    row.classList.toggle("is-open", opening);
    setParams({artifact: opening ? a.id : ""});
  }
  return row;
}

function artifactDetail(a, ctx) {
  const reviews = ctx.reviewsByArtifact.get(a.id) || [];
  const meaning = ctx.lifecycle?.artifact_states?.[a.state]?.meaning || "";
  const moves = ctx.lifecycle?.artifact_states?.[a.state]?.next || [];
  const replacedBy = ctx.items.filter(x => x.supersedes === a.id);
  const noHash = !a.content_hash && ["collected", "quarantined"].includes(a.state);
  return [
    h("dl", {class: "kv ev-kv"},
      h("dt", {}, "State"), h("dd", {}, stateChip(a.usable ? "ok" : a.state === "revoked" ? "critical" : "medium",
                                               complianceLabel("artifactState", a.state).text),
        meaning ? h("span", {class: "sub"}, ` ${meaning}`) : ""),
      h("dt", {}, "Content hash"), h("dd", {}, a.content_hash
        ? h("span", {class: "mono ev-hash"}, a.content_hash) : h("span", {class: "sub"}, "none recorded"),
        h("div", {class: "sub"}, a.integrity_note ||
          "A content hash proves the bytes are unchanged. It does not prove the assertion inside them is true.")),
      h("dt", {}, "Registered"), h("dd", {}, a.collector || "unknown",
        a.collected_at ? ` · ${relativeTime(a.collected_at)} (${localTime(a.collected_at)})` : ""),
      a.supersedes ? [h("dt", {}, "Replaces"), h("dd", {class: "mono"}, a.supersedes)] : "",
      replacedBy.length ? [h("dt", {}, "Replaced by"), h("dd", {class: "mono"}, replacedBy.map(x => x.id).join(", "))] : "",
      a.note ? [h("dt", {}, "Note"), h("dd", {}, a.note)] : ""),
    noHash ? statusLine("No content hash was recorded, so its integrity cannot be confirmed and it can never " +
      "count as evidence. Add it again with the file's SHA-256.", "medium") : "",
    moves.length && can("compliance")
      ? h("div", {class: "bar ev-moves"},
          h("span", {class: "sub"}, "Change state:"),
          moves.filter(to => !(to === "integrity_checked" && !a.content_hash)).map(to => h("button", {
            class: `btn small${to === "available" || to === "integrity_checked" ? " primary" : ""}`, type: "button",
            title: (ARTIFACT_MOVES[to] || [])[1] || "",
            onclick: () => artifactStateModal(a, to)}, (ARTIFACT_MOVES[to] || [humanize(to)])[0])))
      : "",
    h("div", {class: "crit-section-k"}, "Reviews of this document"),
    reviews.length
      ? h("ul", {class: "ev-judged"}, reviews.map(r => h("li", {},
          reviewVerdict(r, a),
          h("span", {}, h("span", {class: "strong"}, criterionTitle(packCriterion(r.criterion_id), r.criterion_id)),
            " ", h("span", {class: "sub mono"}, r.criterion_id)),
          h("span", {class: "sub"}, `as ${evidenceName(r.requirement)}${r.period ? ` · ${r.period}` : ""}`,
            notAsked(r) ? " — this criterion does not need it, so it counts toward nothing" : ""),
          r.reason ? h("span", {class: "sub"}, `“${r.reason}”${r.reviewer ? ` — ${r.reviewer}` : ""}`) : "",
          can("compliance")
            ? h("button", {class: "btn small", type: "button", onclick: () => reviewDecisionModal(r, ctx)},
                icon("check"), "Decide")
            : "")))
      : h("p", {class: "sub"}, "Not sent for review against any criterion yet, so it shows nothing."),
    a.usable && can("compliance")
      ? h("div", {class: "bar"}, h("button", {class: "btn small", type: "button",
          onclick: () => putForwardModal(a)}, icon("plus"), "Send for review"))
      : "",
  ];
}

// A review filed under a requirement its criterion does not ask for.
function notAsked(r) {
  const c = packCriterion(r.criterion_id);
  return Boolean(c && r.requirement &&
    ![...(c.manual_evidence || []), ...(c.fallback_evidence || [])].includes(r.requirement));
}

function reviewVerdict(r, artifact) {
  const stale = r.accepted && artifact && !artifact.usable;
  const tone = stale ? "medium" : r.accepted ? "ok" : r.state === "rejected" ? "critical"
    : r.state === "needs_clarification" ? "medium" : "low";
  return stateChip(tone, stale ? "Accepted, no longer counts" : complianceLabel("reviewState", r.state).text);
}

function artifactState(a) {
  const tone = a.usable ? "ok" : a.state === "revoked" ? "critical" : "medium";
  return h("div", {},
    stateChip(tone, complianceLabel("artifactState", a.state).text),
    a.usable ? "" : h("div", {class: "sub"}, "does not count as evidence yet"));
}

// An artifact is judged per criterion, so the same file can be accepted for one
// obligation and rejected for another. This cell shows all of them.
function evidenceJudgement(reviews, artifact) {
  if (!reviews.length) return h("span", {class: "sub"}, "not reviewed against anything");
  return h("div", {class: "ev-judgement"}, reviews.map(r =>
    h("div", {class: "sub", title: r.criterion_id}, reviewVerdict(r, artifact),
      ` ${criterionTitle(packCriterion(r.criterion_id), r.criterion_id)}`)));
}

function reviewsPanel(reviewed, ctx) {
  const stateSel = selectInput([["", "Any decision"], ...[...new Set(reviewed.map(r => r.state))].sort()
    .map(s => [s, complianceLabel("reviewState", s).text])], param("rstate"), {"aria-label": "Decision"});
  const count = h("span", {class: "result-count", role: "status"}, "");
  const body = h("div", {});
  function draw() {
    const shown = reviewed.filter(r => !stateSel.value || r.state === stateSel.value);
    count.textContent = `${number(shown.length)} of ${number(reviewed.length)}`;
    body.replaceChildren(reviewed.length
      ? table(["Criterion", "Document needed", "Document", "Decision", "Reviewer and reason", ""],
          shown.map(r => {
            const c = packCriterion(r.criterion_id);
            const artifact = ctx.byId.get(r.artifact_id);
            return h("tr", {dataset: {review: r.id || ""}},
              h("td", {}, h("div", {class: "strong"}, criterionTitle(c, r.criterion_id)),
                h("div", {class: "sub mono"}, r.criterion_id)),
              h("td", {}, h("div", {}, evidenceName(r.requirement) || "-"),
                r.requirement ? h("div", {class: "sub mono"}, r.requirement) : "",
                ctx.fallbackFor.get(r.criterion_id)?.has(r.requirement)
                  ? h("div", {}, h("span", {class: "tag evidence-conditional"}, "conditional")) : null,
                notAsked(r)
                  ? h("div", {class: "sub"}, "This criterion does not need it, so it counts toward nothing.") : null),
              h("td", {}, h("div", {}, artifact?.title || r.artifact_id),
                h("div", {class: "sub mono"}, r.artifact_id),
                r.scope || r.period ? h("div", {class: "sub"}, [r.scope, r.period].filter(Boolean).join(" · ")) : ""),
              h("td", {}, reviewVerdict(r, artifact)),
              h("td", {}, h("div", {}, r.reviewer || "-"),
                h("div", {class: "sub"}, r.reason || (r.accepted || r.state === "rejected" ? "no reason recorded" : ""))),
              h("td", {}, can("compliance") ? h("button", {class: "btn small", type: "button",
                onclick: () => reviewDecisionModal(r, ctx)}, "Decide") : ""));
          }))
      : emptyState("Nothing has been reviewed yet. Add a document from a criterion, or send one for review from the document itself."));
  }
  stateSel.addEventListener("change", () => { setParams({rstate: stateSel.value}); draw(); });
  draw();
  return panel("Reviews", [
    h("p", {class: "sub ev-lede"}, "Each row is one decision about one document for one need of one " +
      "criterion. A rejection records what was missing; an acceptance records why it is enough."),
    h("div", {class: "ev-tools", role: "search", "aria-label": "Filter reviews"}, stateSel, count),
    body], null, {className: "ev-panel", dataset: {tab: "reviews"}});
}

// Always-required artifacts are needed whatever the assessment observed.
// Fallback artifacts are conditional: a criterion asks for one only when its
// checks could not establish the property through the store. Listing them
// apart keeps "you must always supply this" from reading like "supply this
// if the store is silent", and the reverse.
function evidenceRequirementsPanel(pack) {
  const byKey = new Map();
  for (const c of pack.criteria || []) {
    for (const [names, kind] of [[c.manual_evidence, "required"], [c.fallback_evidence, "conditional"]]) {
      for (const name of names || []) {
        const key = `${kind}|${name}`;
        const row = byKey.get(key) || {name, kind, criteria: []};
        row.criteria.push(c);
        byKey.set(key, row);
      }
    }
  }
  const rows = [...byKey.values()].sort((a, b) =>
    (a.kind === b.kind ? 0 : a.kind === "conditional" ? -1 : 1) ||
    evidenceName(a.name).localeCompare(evidenceName(b.name)));
  const conditional = rows.filter(r => r.kind === "conditional").length;
  // The tab still opens on something: a pack that asks for no document says so.
  if (!rows.length) {
    return panel("Documents the pack asks for", emptyState("No criterion in this pack asks for a document."),
      null, {className: "ev-panel", dataset: {tab: "supply"}});
  }
  return panel("Documents the pack asks for", [
    h("p", {class: "sub ev-lede"},
      "Always-required documents are needed whatever the checks saw. Conditional " +
      "documents are a fallback: a criterion asks for one only when the store can't " +
      "show the property through its connector, such as encryption at rest on a store that " +
      "does not report it."),
    h("p", {class: "sub"},
      `${number(rows.length - conditional)} always required · ${number(conditional)} conditional`),
    table(["Document", "When it is needed", "Criteria"], rows.map(r => {
      const info = evidenceInfo(r.name);
      return h("tr", {class: `evidence-req evidence-req-${r.kind}`, dataset: {kind: r.kind}},
        h("td", {}, h("div", {class: "strong"}, evidenceName(r.name)),
          info.what ? h("div", {class: "sub"}, info.what) : null,
          (info.examples || []).length
            ? h("div", {class: "sub ev-example"}, `For example: ${info.examples[0]}.`) : null),
        h("td", {}, r.kind === "conditional"
          ? h("span", {class: "tag evidence-conditional"},
              "Conditional — needed only when the store cannot show this property")
          : h("span", {class: "tag evidence-required"}, "Always required")),
        h("td", {}, h("ul", {class: "ev-crit-list"},
          r.criteria.map(c => h("li", {},
            h("button", {class: "link", type: "button",
                         onclick: () => goTo("criteria", {criterion: c.criterion_id})},
              criterionTitle(c)),
            " ", h("span", {class: "tag mono"}, c.criterion_id))))));
    }))], null, {className: "ev-panel", dataset: {tab: "supply"}});
}

// ------------------------------------------------------------ evidence forms ---
// A field with a hint under it and room for its own error, so a validation
// message sits beside what it is about rather than in a toast.
let evidenceFieldSeq = 0;
function hintField(label, input, hint) {
  const id = `ev-f-${++evidenceFieldSeq}`;
  const err = h("span", {class: "field-error", id: `${id}-err`, role: "alert", hidden: true});
  const help = hint ? h("span", {class: "field-hint", id: `${id}-hint`}, hint) : "";
  input.setAttribute("aria-describedby", [hint ? `${id}-hint` : "", `${id}-err`].filter(Boolean).join(" "));
  const wrap = h("label", {class: "field ev-field"}, h("span", {}, label), input, help, err);
  wrap.fail = message => {
    err.textContent = message || "";
    err.hidden = !message;
    if (message) input.setAttribute("aria-invalid", "true");
    else input.removeAttribute("aria-invalid");
    return Boolean(message);
  };
  return wrap;
}

const SHA256 = /^(sha256:)?[0-9a-f]{64}$/i;

async function registerEvidenceModal() {
  const title = textInput("", {placeholder: "e.g. Q3 2026 access review — clinical-rag", required: true, maxlength: "300"});
  const scope = selectInput(storeOptions(["", "Estate-wide (no one store)"]), param("store"), {"aria-label": "Scope"});
  const hash = textInput("", {placeholder: "64 hex characters, e.g. from shasum -a 256", spellcheck: "false"});
  const from = textInput("", {type: "date"});
  const to = textInput("", {type: "date"});
  const replaces = selectInput([["", "Nothing — this is a new document"]], "", {"aria-label": "Replaces"});
  const note = h("textarea", {placeholder: "Optional: where the file lives, who approved it, what it covers", maxlength: "2000"});
  const f = {
    title: hintField("Title", title, "Name the document so a reviewer knows what it is: " +
      "“Signed BAA with Acme Vector Cloud, 2026”, “Record of processing activities v4”."),
    scope: hintField("Store", scope, "The store this document is about. Choose estate-wide for an " +
      "organization-wide policy. A reviewer checks that the document really covers it."),
    hash: hintField("Content hash (SHA-256)", hash, "The file stays in your storage. The hash lets anyone " +
      "confirm later that it is the same file. Without one, its integrity can't be confirmed, " +
      "so it can never count as evidence."),
    from: hintField("Covers from", from, "The window the document evidences. Evidence for Q2 does not evidence Q3."),
    to: hintField("Covers until", to, ""),
    replaces: hintField("Replaces", replaces, "Choose the earlier version this one replaces. It will be " +
      "marked superseded, and acceptances that rested on it stop counting until this one is reviewed."),
    note: hintField("Note", note, ""),
  };
  modal("Add a document", h("div", {class: "evidence-page ev-form"},
    statusLine("Adding records that a document exists and where it applies. " +
               "Whether it evidences an obligation is a separate review.", "info"),
    f.title, f.scope, h("div", {class: "ev-form-pair"}, f.from, f.to), f.hash, f.replaces, f.note),
    async () => {
      const bad = [
        f.title.fail(title.value.trim() ? "" : "Give the document a title a reviewer will recognise."),
        f.hash.fail(!hash.value.trim() || SHA256.test(hash.value.trim()) ? ""
          : "A SHA-256 hash is 64 hexadecimal characters (0–9, a–f), optionally prefixed sha256:."),
        f.to.fail(from.value && to.value && to.value < from.value ? "The end of the period is before its start." : ""),
      ];
      if (bad.some(Boolean)) {
        [title, hash, to][bad.findIndex(Boolean)].focus();
        return;
      }
      await api("/compliance/evidence", {method: "POST", body: JSON.stringify({
        title: title.value.trim(), scope: scope.value, content_hash: hash.value.trim() || null,
        period_start: from.value || null, period_end: to.value || null,
        supersedes: replaces.value || null, note: note.value.trim(),
      })});
      toast(hash.value.trim()
        ? "Document added. Confirm its integrity, then make it ready for review."
        : "Document added without a hash; it can never count as evidence.");
      closeModal();
      route();
    }, "Add document");
  try {
    const list = (await api("/compliance/evidence")).artifacts || [];
    const replaceable = list.filter(a => ["available", "expired"].includes(a.state));
    replaces.replaceChildren(...[["", "Nothing — this is a new document"],
      ...replaceable.map(a => [a.id, `${a.title} (${a.id})`])]
      .map(([value, label]) => h("option", {value}, label)));
  } catch (e) {
    f.replaces.fail(`Earlier documents could not be read: ${unavailableReason(e)}`);
  }
}

function artifactStateModal(a, to) {
  const [label, meaning] = ARTIFACT_MOVES[to] || [humanize(to), ""];
  const reason = h("textarea", {placeholder: to === "integrity_checked"
    ? "e.g. Hash of the file in the policy library matches the recorded hash"
    : "Why the state is changing", maxlength: "2000"});
  const f = hintField("Reason", reason, "Recorded in the audit log with your name.");
  modal(`${label} — ${a.title}`, h("div", {class: "evidence-page ev-form"},
    statusLine(meaning, to === "revoked" ? "medium" : "info"),
    to === "integrity_checked" && a.content_hash
      ? h("p", {class: "sub"}, "Recorded hash: ", h("span", {class: "mono ev-hash"}, a.content_hash)) : "",
    f),
    async () => {
      if (["revoked", "quarantined"].includes(to) && f.fail(reason.value.trim() ? "" : "Say why; the reason is how others will understand this.")) {
        reason.focus();
        return;
      }
      await api(`/compliance/evidence/${encodeURIComponent(a.id)}/state`, {method: "POST",
        body: JSON.stringify({to_state: to, reason: reason.value.trim()})});
      toast(`${a.title}: ${complianceLabel("artifactState", to).text}.`);
      closeModal();
      route();
    }, label);
}

// Put a usable artifact forward for one requirement of one criterion. This
// opens a review; it decides nothing.
function putForwardModal(a) {
  const criteria = state.pack?.criteria || [];
  const criterion = selectInput([["", "Choose a criterion"],
    ...criteria.map(c => [c.criterion_id, `${criterionTitle(c)} (${c.criterion_id})`])], "",
    {"aria-label": "Criterion", required: true});
  const requirement = selectInput([["", "Choose a criterion first"]], "", {"aria-label": "Requirement", required: true});
  const period = textInput("", {placeholder: "e.g. 2026-Q3"});
  const about = h("p", {class: "sub"}, "");
  const f = {
    criterion: hintField("Criterion", criterion, ""),
    requirement: hintField("Document needed", requirement, "Only the documents a criterion asks for are offered."),
    period: hintField("Period under review", period, "Optional. The reviewer judges the artifact for this period."),
  };
  criterion.addEventListener("change", () => {
    const c = criteria.find(x => x.criterion_id === criterion.value);
    const names = c ? [...(c.manual_evidence || []), ...(c.fallback_evidence || [])] : [];
    requirement.replaceChildren(...[["", names.length ? "Choose what it is for" : "This criterion asks for no document"],
      ...names.map(n => [n, evidenceName(n)])].map(([value, label]) => h("option", {value}, label)));
    about.textContent = "";
  });
  requirement.addEventListener("change", () => {
    const info = evidenceInfo(requirement.value);
    about.textContent = requirement.value ? [info.what, info.reviewer_checks && `A reviewer checks: ${info.reviewer_checks}`]
      .filter(Boolean).join(" ") : "";
  });
  modal(`Send for review — ${a.title}`, h("div", {class: "evidence-page ev-form"},
    statusLine("This opens a review of this document for one need. A reviewer then accepts or rejects it.", "info"),
    f.criterion, f.requirement, about, f.period),
    async () => {
      const bad = [f.criterion.fail(criterion.value ? "" : "Choose the criterion this document is for."),
                   f.requirement.fail(requirement.value ? "" : "Choose which document it needs this one to be.")];
      if (bad.some(Boolean)) return;
      await api("/compliance/reviews", {method: "POST", body: JSON.stringify({
        artifact_id: a.id, criterion_id: criterion.value, requirement: requirement.value,
        scope: a.scope || "", period: period.value.trim()})});
      toast("Sent for review.");
      closeModal();
      route();
    }, "Send for review");
}

// The reviewer's decision about one artifact for one requirement. It shows
// what to check, offers only the moves the review can make, and asks why.
function reviewDecisionModal(r, ctx = {}) {
  const artifact = ctx.byId?.get(r.artifact_id) || null;
  const c = packCriterion(r.criterion_id);
  const info = evidenceInfo(r.requirement);
  const next = ctx.lifecycle?.review_states?.[r.state]?.next ||
    ["accepted", "rejected", "needs_clarification"].filter(s => s !== r.state);
  const decision = selectInput([["", "Choose a decision"],
    ...next.map(s => [s, (COMPLIANCE_COPY.labels.reviewMove[s] || {}).text || humanize(s)])],
                               "", {"aria-label": "Decision", required: true});
  const reason = h("textarea", {maxlength: "2000",
    placeholder: "Accept: why it is sufficient — “Signed 2026-02-01, names the clinical-rag corpus, in force for Q3.”\n" +
                 "Reject: what is missing — “Covers H1 only; the period under review is Q3.”"});
  const f = {decision: hintField("Decision", decision, ""),
             reason: hintField("Reason (required)", reason, "Recorded with your name. Another reviewer should be able to check it.")};
  const checklist = [...(state.pack?.reviewer_checklist || []),
    ...(info.reviewer_checks ? [`For ${info.label.toLowerCase()}: ${info.reviewer_checks}`] : [])];
  modal("Decide an evidence review", h("div", {class: "evidence-page ev-form"},
    h("dl", {class: "kv ev-kv"},
      h("dt", {}, "Document"), h("dd", {}, artifact?.title || r.artifact_id, " ", h("span", {class: "sub mono"}, r.artifact_id),
        artifact && !artifact.usable ? h("div", {class: "sub"}, `Its state is “${complianceLabel("artifactState", artifact.state).text}”, so an acceptance would not count.`) : ""),
      h("dt", {}, "Criterion"), h("dd", {}, criterionTitle(c, r.criterion_id), " ", h("span", {class: "sub mono"}, r.criterion_id)),
      h("dt", {}, "Document needed"), h("dd", {}, info.label, info.what ? h("div", {class: "sub"}, info.what) : ""),
      h("dt", {}, "Store and period"), h("dd", {}, [r.scope || "estate-wide", r.period || "no period stated"].join(" · ")),
      h("dt", {}, "Now"), h("dd", {}, reviewVerdict(r, artifact), r.reason ? h("span", {class: "sub"}, ` ${r.reason}`) : "")),
    checklist.length ? h("div", {class: "ev-check-box"},
      h("div", {class: "crit-section-k"}, "Check before deciding"),
      h("ul", {}, checklist.map(item => h("li", {}, item)))) : "",
    f.decision, f.reason),
    async () => {
      const bad = [f.decision.fail(decision.value ? "" : "Choose a decision."),
                   f.reason.fail(reason.value.trim() ? "" : "Say why. A decision without a reason cannot be checked.")];
      if (bad.some(Boolean)) return;
      await api(`/compliance/reviews/${encodeURIComponent(r.id)}`, {method: "POST",
        body: JSON.stringify({to_state: decision.value, reason: reason.value.trim()})});
      toast(`Review saved: ${complianceLabel("reviewState", decision.value).text}.`);
      closeModal();
      route();
    }, "Record decision");
}

// Exceptions: tolerated gaps, with an owner and an expiry. Never a closure.
// ================================================================ actions ===
// One screen at three depths, each an address: the work queue (#/actions), one
// finding's fix (#/actions?fix=<finding>), and one plan (#/actions?plan=<id>).
// Nothing opens over anything else, so every state can be linked and Back works.
//
// The claims the screen must not make: that a plan covers a finding it does not
// reach, that a refusal did not happen, that a guided step was done because
// someone said so, or that a read-back means the finding is gone. Only a re-scan
// that no longer observes a finding resolves it.

let actionsQueueParams = {};

async function renderActions() {
  await loadCore();
  const queueMode = param("queue") === "approval";
  const fix = param("fix") || param("finding");
  const planId = param("plan");
  const box = h("div", {class: "actions-page"});
  // A plan and a fix are records with their own header and a way back; the
  // queue switch belongs to the two lists.
  if (!queueMode && planId) {
    box.append(await planReviewPage(planId));
    return box;
  }
  if (!queueMode && fix) {
    box.append(await remediationPage(fix));
    return box;
  }
  const segments = segmented({label: "Show", options: [["work", "Work queue"], ["approval", "Approval queue"]],
                              value: queueMode ? "approval" : "work", navigates: true,
                              onPick: key => goTo("actions", key === "approval" ? {queue: "approval"} : actionsQueueParams)});
  box.append(pageHeader("actions",
    "Each finding, the fix to try first, and how far it has got.", null, {scope: segments}));
  box.append(queueMode ? await approvalQueueView() : await workQueueView());
  return box;
}

// The way back from a plan or a fix: the work queue, with its filters.
function actionsBack() {
  return {label: "Work queue", className: "remediation-back", onclick: () => climbOut("actions")};
}

// ------------------------------------------------------------ work queue ---

// Where a finding's remediation has got. "verified" is reserved for a re-scan
// (or a case verified by a named run); a read-back that confirmed a write is
// "executed", because the finding is still open until a check stops seeing it.
const WORK_STATES = [
  ["", "Any state"],
  ["proposed", "Proposed"],
  ["staged", "Staged, you can approve"],
  ["awaiting", "Awaiting a second approver"],
  ["approved", "Approved"],
  ["executed", "Executed, not yet verified"],
  ["verified", "Verified by re-scan"],
  ["failed", "Failed or halted"],
];
const WORK_STATE_TONE = {proposed: "info", staged: "info", awaiting: "medium", approved: "info",
                         executed: "high", verified: "ok", failed: "critical", closed: "unknown"};
const WORK_STATE_LABEL = {proposed: "not started", staged: "staged", awaiting: "awaiting approval",
                          approved: "approved", executed: "executed", verified: "verified",
                          failed: "failed", closed: "closed"};
const SEV_RANK = {critical: 0, high: 1, medium: 2, low: 3, info: 4};

function planStageOf(plan) {
  if (!plan) return "";
  const s = plan.summary || {};
  return s.stage || plan.state || "";
}

function workStage(item) {
  const res = item.resolution;
  if (res && !res.claim) return "verified";
  if (res && res.claim) return "closed";
  const stage = planStageOf(item.plan);
  const check = ((item.plan || {}).summary || {}).verification;
  if (["halted", "tampered", "stale", "blocked"].includes(stage)
      || (check && ["failed", "partial"].includes(check.outcome))) return "failed";
  if (stage === "executed" || stage === "verified") return "executed";
  if (stage === "approved" || stage === "executing") return "approved";
  if (stage === "staged") return (item.you || {}).needs_second_person ? "awaiting" : "staged";
  // A guided step marked done moves the case here; it is a claim awaiting a re-scan.
  if (item.case === "awaiting_verification") return "executed";
  return "proposed";
}

// Four steps, drawn small. `at` is the step in progress; everything before it
// is done. A failure is drawn at the step that failed, never as done.
const FIX_STEPS = ["Stage", "Approve", "Run", "Re-scan"];
const GUIDED_STEPS = ["Do it", "Mark done", "Re-scan"];

function remediationStepper(at, {steps = FIX_STEPS, failed = false, label = "Progress"} = {}) {
  return stepList(steps, at, {className: "remediation-steps", label, failed, srPrefix: true});
}

// The work queue's columns, the same in every section so In progress, To do
// and Done line up. The pick and open columns are named for a screen reader.
const WORK_COLUMNS = [{sr: "Select"}, {label: "Finding", className: "actions-page-finding"},
                      {label: "Fix to try first", className: "actions-page-fix"},
                      {label: "Progress", className: "actions-page-state"}, {sr: "Open"}];

function workStepper(item) {
  const stage = workStage(item);
  if (!item.plan && stage === "executed") return remediationStepper(2, {steps: GUIDED_STEPS});
  if (!item.plan && stage === "verified") return remediationStepper(3, {steps: GUIDED_STEPS});
  const at = {staged: 1, awaiting: 1, approved: 2, executed: 3, verified: 4}[stage];
  if (stage === "failed") return remediationStepper(2, {failed: true});
  return at === undefined ? null : remediationStepper(at);
}

async function loadWorkQueue(storeIds, {resolved, disputed}) {
  const [mode, queue] = await Promise.all([
    api("/actions/safe-mode").catch(() => null),
    api("/actions/queue?include_approved=true").catch(() => null),
  ]);
  const you = {};
  for (const p of (queue || {}).plans || []) you[p.plan_id] = p.you || {};
  const stores = await Promise.all(storeIds.map(async store => {
    const enc = encodeURIComponent(store);
    const [suggest, plans] = await Promise.allSettled([
      api(`/stores/${enc}/actions/suggest`, {method: "POST",
        body: JSON.stringify({include_disputed: Boolean(disputed), include_resolved: Boolean(resolved)})}),
      api(`/stores/${enc}/actions/plans`),
    ]);
    return {store,
            body: suggest.status === "fulfilled" ? suggest.value : null,
            error: suggest.status === "rejected" ? suggest.reason : null,
            plans: plans.status === "fulfilled" ? (plans.value || {}).plans || [] : null,
            plansError: plans.status === "rejected" ? plans.reason : null};
  }));
  const items = [];
  let hidden = 0;
  for (const r of stores) {
    if (!r.body) continue;
    const body = r.body;
    hidden += Object.keys(body.resolved || {}).length;
    const meta = body.findings || {};
    const ids = [...new Set([...Object.keys(meta),
                             ...(body.suggestions || []).map(s => s.finding_id),
                             ...(body.guided || []).map(g => g.finding_id),
                             ...(body.withheld || []).map(w => w.finding_id)])];
    const plans = (r.plans || []).slice().sort((a, b) => String(b.staged_at || "").localeCompare(String(a.staged_at || "")));
    for (const id of ids) {
      const m = meta[id] || {};
      const executable = (body.suggestions || []).filter(s => s.finding_id === id);
      const guided = (body.guided || []).filter(g => g.finding_id === id);
      const withheld = (body.withheld || []).filter(w => w.finding_id === id);
      // A passing check is recorded as a finding with nothing to do; it is not work.
      const mine = plans.filter(p => ((p.summary || {}).findings || []).includes(id));
      if (!executable.length && !guided.length && !withheld.length && !mine.length) continue;
      items.push({id, store: r.store, title: m.title, severity: m.severity, collection: m.collection,
                  kind: m.kind, kind_label: m.kind_label, case: m.case, resolution: m.resolution || null,
                  executable, guided, withheld, plans: mine, plan: mine[0] || null,
                  you: mine[0] ? you[mine[0].id] || null : null});
    }
  }
  return {mode, stores, items, hidden, queue};
}

async function workQueueView() {
  const f = {store: param("store"), kind: param("kind"), mode: param("mode"), state: param("state"),
             resolved: param("resolved") === "1", disputed: param("disputed") === "1"};
  actionsQueueParams = {store: f.store, kind: f.kind, mode: f.mode, state: f.state,
                        resolved: f.resolved ? "1" : "", disputed: f.disputed ? "1" : ""};
  const root = h("div", {class: "actions-page-queue"});
  const storeIds = f.store ? [f.store] : state.stores.map(s => s.store_id);
  if (!storeIds.length) {
    root.append(emptyState("No store is registered, so there is nothing to act on.",
      {action: () => goTo("stores"), actionLabel: "Register a store"}));
    return root;
  }
  const [data] = await Promise.all([loadWorkQueue(storeIds, f), approvalsPolicy()]);

  const refetch = changes => goTo("actions", {...actionsQueueParams, ...changes});
  const store = selectInput([["", "All stores"], ...state.stores.map(s => [s.store_id, s.store_id])], f.store);
  store.setAttribute("aria-label", "Store");
  store.onchange = () => refetch({store: store.value});
  const kinds = [...new Map(data.items.map(i => [i.kind, i.kind_label || i.kind])).entries()]
    .filter(([k]) => k).sort((a, b) => String(a[1]).localeCompare(String(b[1])));
  const kind = selectInput([["", "Any finding kind"], ...kinds], f.kind);
  kind.setAttribute("aria-label", "Finding kind");
  const mode = selectInput([["", "Any fix"], ["executable", "VecShield can do it"], ["guided", "You do it"]], f.mode);
  mode.setAttribute("aria-label", "Who carries out the fix");
  const stateSel = selectInput(WORK_STATES, f.state);
  stateSel.setAttribute("aria-label", "Progress");
  // Off by default: a chunk whose every match is a published example or a
  // test key is held back, and including it is a choice made knowingly.
  const disputed = h("input", {type: "checkbox", id: "include-disputed", checked: f.disputed,
                               onchange: () => refetch({disputed: disputed.checked ? "1" : ""})});
  const resolved = h("input", {type: "checkbox", id: "include-resolved", checked: f.resolved,
                               onchange: () => refetch({resolved: resolved.checked ? "1" : ""})});
  const count = h("span", {class: "sub actions-page-count", role: "status"});
  const list = h("div", {class: "actions-page-sections"});
  const notice = h("div", {class: "actions-page-notice"});

  const selected = new Map();
  const stageNote = textInput("", {placeholder: "Why (optional)"});
  stageNote.setAttribute("aria-label", "Reason for staging the selected fixes");
  const stageButton = h("button", {class: "btn primary", type: "button", disabled: true, onclick: stageSelected},
    icon("play"), "Stage selected");
  const stageRefused = h("div", {class: "refusal-slot"});
  // Below the To do list. Once a row is ticked it sticks to the bottom of the
  // window, so the Stage button is in reach from any row of a long list.
  const stageBar = h("div", {class: "actions-page-bulk", role: "group", "aria-label": "Stage the selected fixes"},
    h("span", {class: "sub"}, "Only reversible fixes that need no value can be staged together. Each store gets one plan to review and approve."),
    stageNote, stageButton);

  function pick(item, on) {
    on ? selected.set(item.id, item) : selected.delete(item.id);
    stageButton.disabled = selected.size === 0;
    stageButton.replaceChildren(icon("play"), selected.size ? `Stage selected (${number(selected.size)})` : "Stage selected");
    stageBar.classList.toggle("is-active", selected.size > 0);
  }

  async function stageSelected() {
    stageRefused.replaceChildren();
    const byStore = new Map();
    for (const item of selected.values()) {
      if (!byStore.has(item.store)) byStore.set(item.store, []);
      byStore.get(item.store).push(item.executable[0]);
    }
    const made = [];
    for (const [storeId, suggestions] of byStore) {
      try {
        const plan = await api(`/stores/${encodeURIComponent(storeId)}/actions/plans`, {
          method: "POST",
          body: JSON.stringify({suggestions, note: stageNote.value || `Recommended fixes for ${plural(suggestions.length, "finding")}`}),
        });
        made.push({store: storeId, plan, count: suggestions.length, blocked: blockedOperations(plan)});
      } catch (e) { stageRefused.append(refusalLine(e, `${storeId}: not staged`)); }
    }
    if (!made.length) return;
    actionsNotice = made;
    route();
  }

  function visible() {
    return data.items.filter(item => {
      if (f.kind && item.kind !== f.kind) return false;
      if (f.mode === "executable" && !item.executable.length) return false;
      if (f.mode === "guided" && item.executable.length) return false;
      if (f.state && workStage(item) !== f.state) return false;
      return true;
    });
  }

  function draw() {
    const shown = visible();
    count.textContent = `${plural(shown.length, "finding")}` +
      (shown.length !== data.items.length ? ` of ${number(data.items.length)}` : "");
    const errors = data.stores.filter(r => r.error);
    const planErrors = data.stores.filter(r => !r.error && r.plansError);
    const sections = [];
    for (const r of errors) {
      sections.push(panel(`${r.store}: suggestions`, r.error.status === 503
        ? unavailableState(unavailableReason(r.error), "Suggestions are derived from stored findings.")
        : errorState(unavailableReason(r.error), () => route())));
    }
    for (const r of planErrors) {
      sections.push(statusLine(`Plans for ${r.store} could not be read, so their progress is not shown: ${unavailableReason(r.plansError)}`, "unknown"));
    }
    const started = shown.filter(i => !["proposed", "verified", "closed"].includes(workStage(i)));
    const todo = shown.filter(i => workStage(i) === "proposed");
    const done = shown.filter(i => ["verified", "closed"].includes(workStage(i)));
    const bySev = (a, b) => (b.executable.length ? 1 : 0) - (a.executable.length ? 1 : 0)
      || (SEV_RANK[String(a.severity).toLowerCase()] ?? 9) - (SEV_RANK[String(b.severity).toLowerCase()] ?? 9)
      || String(a.title || "").localeCompare(String(b.title || ""));
    if (started.length) sections.push(panel(`In progress (${number(started.length)})`, workList(started)));
    if (todo.length) sections.push(panel(`To do (${number(todo.length)})`, h("div", {}, workList(todo.sort(bySev)),
      // Siblings of the table, so the bar can stick anywhere along it.
      can("compliance") ? [stageBar, stageRefused] : "")));
    if (done.length) sections.push(panel(`Done (${number(done.length)})`, workList(done)));
    if (!shown.length && !errors.length) {
      sections.push(panel("Work queue", emptyState(data.items.length
        ? "No finding matches these filters."
        : "Nothing is proposed for these findings. Refusals, if any, are listed with each finding.")));
    } else if (!shown.length) {
      sections.push(statusLine("No proposals could be read for the stores above.", "unknown"));
    }
    list.replaceChildren(...sections);
  }

  // Findings that only a person can fix, with the same fix (one library
  // upgrade behind eight advisories in five stores), are one row of work: the
  // findings are listed inside it, each still openable on its own.
  function workList(items) {
    const rows = [];
    const groups = new Map();
    for (const item of items) {
      const guide = !item.executable.length && workStage(item) === "proposed" ? item.guided[0] : null;
      const key = guide ? `${item.kind}\u0000${guide.title}` : null;
      if (!key) { rows.push(item); continue; }
      if (!groups.has(key)) { groups.set(key, {group: true, guide, items: []}); rows.push(groups.get(key)); }
      groups.get(key).items.push(item);
    }
    return table(WORK_COLUMNS, rows.map(entry => entry.group
      ? (entry.items.length > 2 ? workGroupRow(entry) : entry.items.map(workRow))
      : workRow(entry)).flat(), {tableClass: "work-table", wrapClass: "table-wrap work-table-wrap"});
  }

  function workGroupRow({guide, items}) {
    const sorted = items.slice().sort((a, b) =>
      (SEV_RANK[String(a.severity).toLowerCase()] ?? 9) - (SEV_RANK[String(b.severity).toLowerCase()] ?? 9));
    const stores = [...new Set(items.map(i => i.store))];
    const first = sorted[0];
    return h("tr", {class: "actions-page-row actions-page-row-group"},
      h("td", {class: "actions-page-pick"}),
      h("td", {class: "actions-page-finding"},
        h("div", {class: "actions-page-title"}, badge(first.severity),
          h("span", {class: "strong"}, `${plural(items.length, "finding")} with one fix`)),
        h("div", {class: "sub"}, `${first.kind_label || first.kind || "Findings"} \u00b7 ${plural(stores.length, "store")}`),
        h("details", {class: "actions-page-more"},
          h("summary", {}, `List the ${plural(items.length, "finding")}`),
          h("ul", {class: "actions-page-alts"}, sorted.map(i => h("li", {}, badge(i.severity), " ",
            h("button", {class: "link", type: "button", onclick: () => goTo("actions", {fix: i.id})}, i.title || i.id),
            h("span", {class: "sub"}, ` \u00b7 ${i.store}`)))))),
      h("td", {class: "actions-page-fix"},
        h("div", {}, h("span", {class: "actions-page-who"}, stateChip("unknown", "You", {glyph: "user", title: "A person carries it out; VecShield verifies it by re-scan."})),
          " ", h("span", {class: "strong"}, guide.title),
          h("div", {class: "sub"}, `${guide.owner || ""}${guide.owner ? " \u00b7 " : ""}verify each finding by re-scan once it is done`))),
      h("td", {class: "actions-page-state"}, stateChip("info", "not started")),
      h("td", {class: "actions-page-open"},
        h("button", {class: "btn small", type: "button", "aria-label": `Fix: ${guide.title}, starting with ${first.title || first.id}`,
                     onclick: () => goTo("actions", {fix: first.id})}, "Fix")));
  }

  function workRow(item) {
    const stage = workStage(item);
    const lead = item.executable[0] || null;
    const guide = !lead ? item.guided[0] || null : null;
    const safeBulk = can("compliance") && lead && stage === "proposed" && lead.reversible && !(lead.needs_params || []).length;
    const others = item.executable.slice(1).length + item.guided.length - (guide ? 1 : 0);
    const plan = item.plan;
    const s = (plan || {}).summary || {};
    // A plan staged for several findings lists only this finding's part.
    const allOps = s.operations || [];
    const ownOps = allOps.filter(o => !o.finding_id || o.finding_id === item.id);
    const progress = plan
      ? h("div", {class: "sub"},
          h("span", {class: "mono"}, plan.id), " · ",
          ownOps.map(o => `${o.title}${o.collection ? ` · ${o.collection}` : ""}` +
            (o.params && o.params.tenant_value ? ` → ${o.params.tenant_value}` : "")).join("; "),
          allOps.length > ownOps.length ? ` (+${plural(allOps.length - ownOps.length, "other fix", "other fixes")} in this plan)` : "",
          s.verification
            ? ` · read-back ${s.verification.outcome}: ${number(s.verification.observed || 0)} of ${number(s.verification.expected || 0)}`
            : "")
      : "";
    const resolution = item.resolution
      ? h("div", {class: "sub"}, item.resolution.claim
          ? `Case ${item.resolution.label}: a person's claim, not a run's.`
          : `No longer observed by run ${item.resolution.job_id || "?"} ${item.resolution.at ? relativeTime(item.resolution.at) : ""}.`)
      : "";
    const openLabel = stage === "proposed" ? "Fix" : ["verified", "closed"].includes(stage) ? "View" : "Continue";
    // Every row's button is a quiet one: a column of accent buttons down a
    // list of a hundred is noise. The one primary here is Stage selected.
    return h("tr", {class: `actions-page-row actions-page-row-${stage}`},
      h("td", {class: "actions-page-pick"}, safeBulk
        ? hitBox(h("input", {type: "checkbox", "aria-label": `Select ${item.title || item.id}`,
                             checked: selected.has(item.id),
                             onchange: event => pick(item, Boolean(event?.target?.checked))}))
        : ""),
      h("td", {class: "actions-page-finding"},
        h("div", {class: "actions-page-title"}, badge(item.severity),
          h("button", {class: "link strong", type: "button", onclick: () => goTo("actions", {fix: item.id})},
            item.title || item.id)),
        h("div", {class: "sub"}, `${item.store} / ${item.collection || "store scope"}`,
          item.kind_label ? ` · ${item.kind_label}` : ""),
        progress, resolution),
      h("td", {class: "actions-page-fix"},
        lead
          ? h("div", {}, h("span", {class: "actions-page-who"}, stateChip("info", "VecShield", {glyph: "shield", title: "VecShield performs it through the store's connector, after approval."})),
              " ", h("span", {class: "strong"}, lead.title),
              h("div", {class: "sub"}, reachText(lead)),
              h("div", {class: "remediation-chips"},
                lead.reversible ? stateChip("info", "reversible", {glyph: "refresh"}) : stateChip("critical", "cannot be undone"),
                basisChip(lead),
                (lead.needs_params || []).length && stage === "proposed" ? stateChip("medium", "needs a value", {title: "Stage it from the fix page, where the value is asked for."}) : ""),
              excludedList(lead))
          : guide
          ? h("div", {}, h("span", {class: "actions-page-who"}, stateChip("unknown", "You", {glyph: "user", title: "A person carries it out; VecShield verifies it by re-scan."})),
              " ", h("span", {class: "strong"}, guide.title),
              h("div", {class: "sub"}, guide.owner || ""))
          : item.withheld.length ? h("span", {class: "sub"}, "Nothing is proposed; see why below.")
          : h("span", {class: "sub"}, "No fix is proposed now."),
        others || item.withheld.length
          ? h("details", {class: "actions-page-more"},
              h("summary", {}, [others ? plural(others, "other fix", "other fixes") : "",
                                item.withheld.length ? `${number(item.withheld.length)} withheld` : ""].filter(Boolean).join(" · ")),
              workAlternatives(item, lead, guide))
          : ""),
      h("td", {class: "actions-page-state"},
        stage === "executed" && item.case === "in_progress"
          ? stateChip("high", "still open", {title: "It ran, and the finding is still open: a re-scan still observed it, or the read-back did not confirm it."})
          : stateChip(WORK_STATE_TONE[stage] || "info", WORK_STATE_LABEL[stage] || stage),
        workStepper(item) || ""),
      h("td", {class: "actions-page-open"},
        h("button", {class: "btn small", type: "button",
                     "aria-label": `${openLabel}: ${item.title || item.id}`,
                     onclick: () => goTo("actions", {fix: item.id})}, openLabel)));
  }

  function workAlternatives(item, lead, guide) {
    const rows = [];
    for (const s of item.executable) {
      if (s === lead) continue;
      rows.push(h("li", {}, stateChip("info", "VecShield", {glyph: "shield"}), " ", h("span", {class: "strong"}, s.title),
        " ", s.reversible ? stateChip("info", "reversible", {glyph: "refresh"}) : stateChip("critical", "cannot be undone"),
        h("div", {class: "sub"}, reachText(s)), excludedList(s)));
    }
    for (const g of item.guided) {
      if (g === guide) continue;
      rows.push(h("li", {}, stateChip("unknown", "You", {glyph: "user"}), " ", h("span", {class: "strong"}, g.title),
        h("div", {class: "sub"}, g.owner || "")));
    }
    return h("div", {},
      rows.length ? h("ul", {class: "actions-page-alts"}, rows) : "",
      item.withheld.length
        ? h("div", {class: "actions-page-withheld"},
            h("div", {class: "metric-k"}, `Withheld (${number(item.withheld.length)})`),
            h("ul", {class: "limitations"}, item.withheld.map(w => h("li", {},
              h("span", {class: "strong"}, w.title || w.action), ": ", w.reason))))
        : "");
  }

  for (const sel of [kind, mode, stateSel]) {
    sel.onchange = () => {
      f.kind = kind.value; f.mode = mode.value; f.state = stateSel.value;
      actionsQueueParams = {...actionsQueueParams, kind: f.kind, mode: f.mode, state: f.state};
      setParams({kind: f.kind, mode: f.mode, state: f.state});
      draw();
    };
  }

  if (actionsNotice) {
    const made = actionsNotice;
    actionsNotice = null;
    notice.append(h("div", {class: "actions-page-staged", role: "status"},
      made.map(m => h("div", {class: "bar"},
        h("span", {}, m.blocked && m.blocked.length
          ? `Staged ${m.plan.id}: ${plural(m.count, "fix", "fixes")} on ${m.store}, but ${number(m.blocked.length)} cannot run (${m.blocked[0].support_reason || "blocked"}). Review it before approving.`
          : `Staged ${m.plan.id}: ${plural(m.count, "fix", "fixes")} on ${m.store}. Approve it next.`),
        h("button", {class: "btn small primary", type: "button", onclick: () => goTo("actions", {plan: m.plan.id})},
          "Review and approve")))));
  }

  root.append(
    workDeployment(data.mode),
    toolbar("Filter the work queue", [
      store, kind, mode, stateSel,
      h("label", {for: "include-resolved", class: "check-row"}, resolved,
        h("span", {}, data.hidden ? `Show resolved (${number(data.hidden)})` : "Show resolved")),
      h("label", {for: "include-disputed", class: "check-row"}, disputed,
        h("span", {title: "Chunks whose every match is disputed as not a live value (a published example, a test key) are left out unless you include them."},
          "Include disputed-only chunks")),
      count], {className: "findings-tools actions-page-filters"}),
    notice, list);
  draw();
  return root;
}

let actionsNotice = null;

// Whether this deployment can write, and who approves, said once at the top.
// A reader who works through a plan and only learns at the last step that
// nothing can run has been wasted.
function workDeployment(mode) {
  const actions = (mode || {}).actions || [];
  const reachable = actions.filter(a => a.reachable).length;
  return h("div", {class: "actions-page-deploy"},
    safeModeLine(mode),
    approvalLine(),
    actions.length
      // An action that is implemented but gated shut is not "available".
      ? h("details", {class: "evidence-data actions-page-capabilities"},
          h("summary", {}, `Which actions can run here (${number(reachable)} of ${number(actions.length)})`),
          table(["Action", "Reachable", "Why not"],
            actions.map(a => h("tr", {},
              h("td", {}, a.title, a.reversible ? "" : [" ", stateChip("critical", "irreversible")]),
              h("td", {}, a.reachable ? stateChip("ok", "yes") : stateChip("unknown", "no")),
              h("td", {class: "sub"}, a.blocked_by || "-")))))
      : "");
}

function safeModeLine(mode) {
  if (!mode) return statusLine("Whether this deployment permits writes could not be read.", "unknown");
  if (!mode.safe_mode) {
    return statusLine("Writes are on (safe mode off). Every run is recorded as such and read back.", "warn");
  }
  return h("div", {class: "remediation-safemode"},
    statusLine(mode.note || "Writes are blocked: you can stage and approve, but nothing runs.", "medium"),
    mode.how_to_enable
      ? h("details", {class: "evidence-data"},
          h("summary", {}, icon("lock"), "How to allow execution"),
          h("p", {class: "sub"}, mode.how_to_enable),
          h("code", {class: "remediation-code"}, `${mode.variable || "VECSHIELD_SAFE_MODE"}=0`))
      : "");
}

// Who approves, in the deployment's own terms. With no sign-in every caller is
// one admin, so the demo path is approve-your-own; the sentence says what
// changes when sign-in is on rather than letting the demo stand for production.
function approvalLine() {
  const policy = state.approvals || {};
  const mode = policy.separation_of_duties || "required";
  if (mode === "admin_may_self_approve" && policy.source === "default") {
    return statusLine("No sign-in here, so you approve your own reversible plans; each approval is " +
      "recorded as self-approved. With sign-in on, a second person approves.", "info");
  }
  return statusLine(approverSentence("a plan"), "info");
}

// Plans waiting for a person, across every store. Whether you may approve is
// the server's preview of its own rule; the approve step still decides.
async function approvalQueueView() {
  let body;
  try { body = await api("/actions/queue"); }
  catch (e) {
    return panel("Approval queue", e.status === 503
      ? unavailableState(unavailableReason(e), "Plans are stored with scan history.")
      : errorState(unavailableReason(e), () => route()));
  }
  await approvalsPolicy();
  const plans = body.plans || [];
  const mine = plans.filter(p => (p.you || {}).may_approve);
  const second = plans.filter(p => !(p.you || {}).may_approve && (p.you || {}).needs_second_person);
  const blocked = plans.filter(p => !(p.you || {}).may_approve && !(p.you || {}).needs_second_person);
  // A plan with nothing to qualify it says nothing in the last column, rather
  // than a dash that reads like a missing value.
  const row = p => h("tr", {},
    h("td", {class: "aq-plan"}, h("span", {class: "mono"}, p.plan_id), p.note ? h("div", {class: "sub"}, p.note) : ""),
    h("td", {class: "mono"}, p.store, p.store_registered === false ? h("div", {}, stateChip("unknown", "no longer registered")) : ""),
    h("td", {}, p.staged_by || "-", (p.you || {}).self_proposed ? h("div", {class: "sub"}, "you proposed it") : ""),
    h("td", {}, formatWhen(p.staged_at)),
    h("td", {}, `${number(p.executable || 0)} of ${number(p.operations || 0)} can run`,
      p.irreversible ? h("div", {}, stateChip("critical", `${number(p.irreversible_operations || 0)} irreversible`)) : ""),
    h("td", {}, (p.you || {}).reason ? h("span", {class: "sub"}, p.you.reason)
                                     : (p.you || {}).would_be_self_approval
                                       ? stateChip("medium", "would be self-approved", {title: "You proposed it; this deployment lets you approve it, and records that."})
                                       : ""),
    h("td", {class: "aq-open"}, h("button", {class: "btn small", type: "button", onclick: () => goTo("actions", {plan: p.plan_id})},
      icon("eye"), "Review")));
  const group = (title, list, empty) => panel(`${title} (${number(list.length)})`, list.length
    ? table(["Plan", "Store", "Staged by", "Staged", "Operations", "Why", {sr: "Open"}], list.map(row),
            {tableClass: "approval-table"})
    : emptyState(empty));
  // The same two lines the work queue opens with: what approving does here,
  // and who may approve.
  return h("div", {class: "actions-page-queue"},
    h("div", {class: "actions-page-deploy"}, statusLine(body.note || "", "info"), approvalLine()),
    group("You can approve", mine, "No staged plan is waiting for your approval."),
    group("Needs a second person", second, "No plan here needs someone other than you."),
    blocked.length ? group("You cannot approve", blocked, "") : "");
}

// A proposal's reach, in one sentence: what it touches and, where the finding
// counted more than it named, both numbers.
function reachText(s) {
  const where = s.collection ? `in ${s.collection}` : "at store scope";
  if (s.scope === "collection") return `The collection ${s.collection || ""} itself; no chunk is changed.`;
  if (s.selector_text) return `${s.selector_text} ${where}, found when you stage it.`;
  const n = (s.chunk_ids || []).length;
  return s.reaches_all_observed
    ? `${plural(n, "chunk")} ${where}.`
    : `${number(n)} of ${number(s.observed_chunks)} chunks ${where}: the assessment retained only a sample of ids` +
      ((s.excluded || []).length ? `, and ${plural(s.excluded.length, "named chunk")} held back.` : ".");
}

function capitalize(text) {
  const value = String(text || "");
  return value ? value[0].toUpperCase() + value.slice(1) : value;
}

function excludedList(s) {
  if (!(s.excluded || []).length) return "";
  return h("details", {class: "evidence-data"},
    h("summary", {}, `${plural(s.excluded.length, "named chunk")} held back`),
    h("ul", {class: "limitations"}, s.excluded.map(e => h("li", {},
      h("span", {class: "mono"}, e.chunk_id), ": ", e.reason))));
}

function basisChip(s) {
  if (s.basis === "condition") return stateChip("info", "observed condition", {title: "A metadata condition, re-read from the store when staged."});
  if (s.basis === "check") return stateChip("info", "deterministic check", {title: "A probe result, not a detector's judgement."});
  if (s.basis === "statistical") return stateChip("unknown", "statistical outlier", {title: "An outlier score, which is weak evidence on its own."});
  return s.calibrated ? stateChip("ok", "measured detector") : stateChip("unknown", "unmeasured detector");
}

// ------------------------------------------------------------- plan pages ---

// The diff a reviewer reads before approving. Warnings first, deliberately:
// they are what a reviewer skims past.
function planDiffView(plan, {open = true, warnings: showWarnings = true} = {}) {
  const radius = plan.blast_radius || {};
  const warnings = (plan.review || {}).warnings || [];
  const ops = plan.operations || [];
  return h("details", {class: "remediation-diff", open: open || null},
    h("summary", {}, icon("eye"), `Review the diff: ${plural(radius.chunks_targeted || 0, "chunk")} reached` +
      (warnings.length ? `, ${plural(warnings.length, "warning")}` : "")),
    !showWarnings ? ""
      : warnings.length
      ? h("div", {}, h("div", {class: "metric-k"}, "Before you read the operations"),
          h("ul", {class: "limitations"}, warnings.map(w => h("li", {}, w))))
      : statusLine("Nothing about this plan needs a warning.", "ok"),
    h("p", {class: "sub"},
      `${number(radius.executable || 0)} of ${plural(radius.operations || 0, "operation")} can run · ` +
      `${plural(radius.chunks_targeted || 0, "chunk")} reached ` +
      (radius.reaches_all_observed ? "(all the findings observed)" : `of ${number(radius.chunks_observed_by_findings || 0)} observed`) +
      ` · ${number(radius.irreversible_chunks || 0)} irreversible`),
    ops.map(op => h("div", {class: "remediation-op"},
      h("div", {class: "spread"},
        h("span", {class: "strong"}, op.title),
        op.supported ? stateChip("ok", "can run") : stateChip("unknown", "blocked")),
      h("p", {class: "sub"}, op.supported
        ? `${number(op.resolved)} present, ${number(op.missing)} missing`
          + (op.unchecked ? `, ${number(op.unchecked)} never looked up` : "")
        : op.support_reason),
      op.selector_text
        ? h("p", {class: "sub"}, `Targets: ${op.selector_text}` +
            ((op.selection || {}).capped
              ? ` (${number(op.selection.matched)} matched; this plan reaches the first ${number(op.selection.reached)})`
              : ""))
        : "",
      planParams(op),
      op.verification ? h("p", {class: "sub"}, `Checked after running: ${op.verification}`) : "",
      h("p", {class: "sub"}, `Undo: ${op.undo}`),
      op.caveat ? h("p", {class: "sub"}, `Does not: ${op.caveat}`) : "",
      (op.sample || []).length
        ? h("ul", {class: "limitations"},
            op.sample.map(t => h("li", {},
              h("button", {class: "link mono", type: "button",
                           title: "Open this chunk as the store holds it now",
                           onclick: () => openChunk({store: plan.store, collection: t.collection || op.collection,
                                                     chunkId: t.chunk_id})},
                t.chunk_id, " ", icon("eye")),
              ": ", t.preview || "(no text)",
              // A redaction is approved as the exact replacement.
              t.redacted_preview !== undefined
                ? h("div", {class: "sub"}, "→ ", h("span", {class: "mono"}, t.redacted_preview))
                : "")))
        : "")),
    statusLine((plan.review || {}).execution_note || "", "info"));
}

// One plan on its own page: the diff, then approve and run. Reached from the
// approval queue and from bulk staging.
async function planReviewPage(planId) {
  return h("div", {class: "remediation-page"},
    pageHeader(recordTitle("Plan", planId), "What this plan changes, then approve and run it.", null,
               {back: actionsBack(), titleClass: "remediation-title"}),
    await planReview(planId));
}

async function planReview(planId) {
  const body = h("div", {class: "remediation-plan-review"});
  try {
    const plan = await api(`/actions/plans/${encodeURIComponent(planId)}/diff`);
    // Two surfaces, read in order: what the plan changes, then the decision.
    body.replaceChildren(
      h("section", {class: "remediation-card", "aria-label": "What this plan changes"}, planDiffView(plan)),
      h("section", {class: "remediation-card", "aria-label": "Approve and run"},
        await planDecisionBar(planId, plan)));
  } catch (e) {
    body.replaceChildren(e.status === 409
      ? unavailableState(unavailableReason(e),
          "A plan that no longer matches its hash cannot be reviewed.")
      : errorState(unavailableReason(e), null));
  }
  return body;
}

function planParams(op) {
  const params = op.params || {};
  const rows = [];
  if (params.tenant_value) rows.push(["Tenant written", `${params.tenant_field} = ${params.tenant_value}`]);
  if (params.reason) rows.push(["Review reason", params.reason]);
  if (params.status) rows.push(["Provenance tag", params.status]);
  for (const [tenant, part] of Object.entries(params.partitions || {})) {
    rows.push([`Tenant ${tenant}`, `${plural(part.chunks || 0, "chunk")} → ${part.collection}${part.exists ? " (exists)" : ""}`]);
  }
  if (!rows.length) return "";
  return h("dl", {class: "kv remediation-kv"},
    rows.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {class: "mono"}, v)]));
}

// What a run observed when it read the store back. "Confirmed" still carries
// the caveats, because each says what the write did not establish.
function verificationBlock(check) {
  if (!check) return statusLine("The store was not read back after this run.", "unknown");
  const tone = {confirmed: "ok", partial: "high", inconclusive: "unknown", failed: "critical"}[check.outcome] || "unknown";
  return h("div", {class: "remediation-verify"},
    h("div", {},
      stateChip(tone, `read-back: ${check.outcome}`), " ",
      h("span", {class: "sub"}, `${number(check.observed || 0)} of ${number(check.expected || 0)} observed` +
        (check.unreadable ? `, ${number(check.unreadable)} unreadable` : ""))),
    check.reason ? h("p", {class: "sub"}, check.reason) : "",
    (check.caveats || []).length
      ? h("details", {class: "evidence-data"},
          h("summary", {}, `What the read-back does not establish (${number(check.caveats.length)})`),
          h("ul", {class: "limitations"}, check.caveats.map(c => h("li", {}, c))))
      : "");
}

// Approving is typing a reason, deliberately. A single "Approve" button would
// make authorizing a change to customer data the easiest thing on the screen.
async function planDecisionBar(planId, plan, {onChange = null} = {}) {
  const box = h("div", {class: "remediation-decision"});
  const reason = textInput("", {placeholder: "Why this is being approved"});
  reason.setAttribute("aria-label", "Reason for approving");
  const typed = textInput("", {placeholder: `Type ${plan.store} to confirm`});
  typed.setAttribute("aria-label", "Store id, to confirm an irreversible change");
  const needsTyping = (plan.operations || []).some(op => op.runnable && !op.reversible);
  const out = h("div", {});
  const ran = h("div", {});
  // A refusal is said here, beside the controls, in the server's words.
  const refused = h("div", {class: "refusal-slot"});
  // Read once: whether this deployment can write at all. Unknown is not "yes".
  const mode = await api("/actions/safe-mode").catch(() => null);
  const findingIds = [...new Set((plan.operations || []).map(op => op.finding_id).filter(Boolean))];

  async function refresh() {
    try {
      const body = await api(`/actions/plans/${encodeURIComponent(planId)}/executions`);
      out.replaceChildren(decisionHistory(body));
    } catch (e) {
      out.replaceChildren(statusLine(unavailableReason(e), "unknown"));
    }
  }

  async function approve() {
    refused.replaceChildren();
    try {
      await api(`/actions/plans/${encodeURIComponent(planId)}/approve`, {
        method: "POST",
        body: JSON.stringify({reason: reason.value,
                              typed_store_id: needsTyping ? typed.value : ""}),
      });
      toast("Approved. It runs only when someone executes it.", "ok");
      reason.value = "";
      await refresh();
      if (onChange) await onChange();
    } catch (e) { refused.replaceChildren(refusalLine(e, "Not approved")); }
  }

  async function execute(approvalId) {
    refused.replaceChildren();
    try {
      const result = await api(`/actions/plans/${encodeURIComponent(planId)}/execute`, {
        method: "POST", body: JSON.stringify({approval_id: approvalId, verify: true}),
      });
      // Never "Done": the read-back is the claim, and even a confirmed one
      // leaves the finding open until a re-scan stops observing it.
      const check = result.verification || {};
      toast(`${result.complete ? "Executed" : result.halted ? "Halted" : "Partially applied"}; read-back ${check.outcome || "not run"}. Re-scan to confirm.`,
            result.complete ? "ok" : "err");
      ran.replaceChildren(h("div", {class: "metric-k"}, "What the read-back observed"),
        verificationBlock(result.verification),
        findingIds.length
          ? h("div", {class: "bar"}, findingIds.map(fid =>
              h("button", {class: "btn small primary", type: "button", onclick: () => goTo("actions", {fix: fid})},
                icon("refresh"), `Re-scan ${fid} to confirm`)))
          : "");
      await refresh();
      if (onChange) await onChange();
    } catch (e) { refused.replaceChildren(refusalLine(e, "Not executed")); }
  }

  // A plan that has run, halted, or gone stale is not something to approve.
  const open = !plan.state || plan.state === "staged";
  await approvalsPolicy();
  box.append(
    h("div", {class: "metric-k"}, "Approve"),
    open
      ? h("p", {class: "sub"}, `${approverSentence("this plan")} `
          + "Approval covers this exact plan; re-staging needs a fresh one.")
      : statusLine(`This plan is ${plan.state} and cannot be approved again. `
          + "Stage a fresh plan for further changes.", "medium"),
    open && !can("compliance")
      ? h("p", {class: "gated-why"}, icon("lock"), roleNeed("compliance"))
      : open
      ? h("div", {class: "bar"}, reason,
          needsTyping ? typed : "",
          h("button", {class: "btn primary", type: "button", onclick: approve}, "Approve"))
      : "",
    refused,
    ran,
    out,
    findingIds.length
      ? h("p", {class: "sub"}, "Fixes ", findingIds.flatMap((fid, i) => [i ? ", " : "",
          h("button", {class: "link mono", type: "button", onclick: () => goTo("actions", {fix: fid})}, fid)]), ".")
      : "");
  box._execute = execute;
  await refresh();
  return box;

  function decisionHistory(body) {
    const approvals = body.approvals || [];
    const executions = body.executions || [];
    if (!approvals.length && !executions.length) {
      return statusLine("Nobody has approved this plan.", "info");
    }
    return h("div", {},
      approvals.length
        ? table(["Approved by", "When", "Reason", ""],
            approvals.map(a => h("tr", {},
              h("td", {}, a.approver, a.self_approved ? [" ", selfApprovedChip()] : ""),
              h("td", {}, formatWhen(a.approved_at)),
              h("td", {}, a.reason),
              h("td", {}, open
                ? (mode && mode.safe_mode
                    // Visible but not pressable, with the reason beside it: a
                    // missing control would read as "nothing to do".
                    ? h("span", {}, h("button", {class: "btn small danger", type: "button", disabled: true,
                                                 title: mode.how_to_enable || ""}, "Execute"),
                        h("div", {class: "sub"}, `Safe mode is on. Set ${mode.variable || "VECSHIELD_SAFE_MODE"}=0 on the server to run it.`))
                    : gated("compliance", h("button", {class: "btn small danger", type: "button",
                                   onclick: () => execute(a.id)}, "Execute")))
                : h("span", {class: "sub"}, "used")))))
        : "",
      executions.length
        ? table(["Ran", "By", "Outcome", "Read-back"],
            executions.map(e => h("tr", {},
              h("td", {}, formatWhen(e.started_at)),
              h("td", {}, e.executed_by),
              h("td", {}, e.halted ? stateChip("unknown", "halted")
                                   : stateChip("ok", "ran")),
              h("td", {}, e.verification
                ? stateChip({confirmed: "ok", partial: "high", failed: "critical"}[e.verification.outcome] || "unknown",
                            e.verification.outcome, {title: e.verification.reason || ""})
                : h("span", {class: "sub"}, "-")))))
        : "");
  }
}

// ------------------------------------------------------------ fix a finding ---
// What can be done about one finding, as one flow: pick a fix (the recommended
// one is already picked), read what it changes, stage it, approve it, run it,
// and re-scan. "VecShield does it" runs through a connector behind approval and
// safe mode; "you do it" is a procedure for somewhere VecShield cannot reach,
// and marking it done records a claim that only a re-scan can verify.

const RISK_TONE = {low: "ok", medium: "medium", high: "critical"};
const RESCAN_TONE = {resolved: "ok", still_present: "high", inconclusive: "unknown", unsupported: "unknown"};
const RESCAN_LABEL = {resolved: "no longer observed", still_present: "still observed",
                      inconclusive: "inconclusive", unsupported: "not re-runnable here"};

// The finding drawer's way in. It navigates rather than opening a panel over
// the drawer: the fix is a page with its own address.
function openRemediation(finding) {
  const id = typeof finding === "string" ? finding : finding.id;
  goTo("actions", {fix: id});
}

async function remediationPage(id) {
  const root = h("div", {class: "remediation-page"});
  // After an action the page is redrawn from the server, and focus goes to the
  // control for the next step (or the outcome), not back to the top.
  async function load(focusKey = "") {
    let view;
    try {
      view = await api(`/admin/findings/${encodeURIComponent(id)}/remediation`);
    } catch (e) {
      root.replaceChildren(pageHeader(["Fix for ", h("span", {class: "mono"}, id)], undefined, null,
                                      {back: actionsBack(), titleClass: "remediation-title"}),
        e.status === 503
          ? unavailableState(unavailableReason(e), "Remediation is worked out from stored findings.")
          : errorState(unavailableReason(e), () => load()));
      return;
    }
    await approvalsPolicy();
    const plan = (view.plans || []).slice().sort((a, b) => String(b.staged_at || "").localeCompare(String(a.staged_at || "")))[0] || null;
    let diff = null;
    if (plan && ["staged", "approved"].includes(planStageOf(plan))) {
      diff = await api(`/actions/plans/${encodeURIComponent(plan.id)}/diff`).catch(e => ({error: e}));
    }
    root.replaceChildren(remediationView(view, {reload: load, plan, diff}));
    if (focusKey) root.querySelector?.(`[data-focus="${focusKey}"]`)?.focus?.();
  }
  await load();
  return root;
}

// The latest re-scan recorded after `since` (an ISO time or epoch seconds).
function rescanSince(view, since) {
  const from = typeof since === "number" ? since * 1000 : Date.parse(since || "");
  if (!Number.isFinite(from)) return null;
  const after = (view.rescans || []).filter(r => r.at * 1000 >= from);
  return after[after.length - 1] || null;
}

// What the re-scan said after this plan last ran, if one has.
function planRescan(plan, view) {
  const ran = (((plan || {}).summary || {}).executions || [])[0];
  return ran ? rescanSince(view, ran.started_at) : null;
}

function remediationView(view, {reload, plan = null, diff = null}) {
  const exec = view.executable || [];
  const guided = view.guided || [];
  // A plan on its way (staged, approved, run and awaiting a re-scan) leads;
  // one that halted, went stale, or ran without removing the finding leaves
  // the choice open again.
  const after = planRescan(plan, view);
  const inFlight = plan && !view.resolution
    && !["halted", "tampered", "stale", "blocked", "withdrawn"].includes(planStageOf(plan))
    && !(after && after.outcome === "still_present");
  const nothing = !exec.length && !guided.length && !(view.plans || []).length;
  return h("div", {class: "remediation-view"},
    remediationHead(view),
    view.resolution && !inFlight ? "" : h("div", {class: "remediation-status"},
      exec.length || (view.plans || []).length ? safeModeLine(view.safe_mode) : "",
      exec.length || (view.plans || []).length ? approvalLine() : ""),
    plan ? remediationPlanFlow(plan, view, {reload, diff}) : "",
    nothing
      ? emptyState(view.note || "Nothing is catalogued for this finding.")
      : remediationChooser(view, {reload, secondary: Boolean(inFlight || view.resolution)}),
    remediationRescans(view, {reload}));
}

function remediationHead(view) {
  const f = view.finding || {};
  const res = view.resolution;
  const kase = view.case || {};
  return h("section", {class: "remediation-head", "aria-labelledby": "page-title"},
    pageHeader([badge(f.severity), " ", f.title || f.id], undefined,
      h("button", {class: "btn small", type: "button", onclick: () => goTo("findings", {finding: f.id})},
        icon("eye"), "Open the finding"),
      {back: actionsBack(), titleClass: "remediation-title"}),
    h("div", {class: "remediation-meta"},
      h("span", {class: "sub mono"}, `${view.store_id || f.store || "?"} / ${f.collection || "store scope"}`),
      stateChip("info", view.kind_label || view.kind || "finding", {glyph: "tag"}),
      h("span", {class: "sub"}, "Case"), caseBadge(kase.state),
      view.store_registered ? "" : stateChip("unknown", "store no longer registered")),
    res
      ? res.claim
        ? statusLine(`Case ${res.label}${res.reason ? `: ${res.reason}` : ""}. A person's claim; no run verified it.`, "medium")
        : h("div", {class: "remediation-resolved"},
            statusLine(`Resolved: re-scan ${res.job_id || ""} ${res.at ? relativeTime(res.at) : ""} no longer observes this finding.`, "ok"),
            res.job_id ? h("button", {class: "link", type: "button", onclick: () => goTo("history", {scan: res.job_id})},
              "Open that run") : "")
      : "",
    view.newer_record
      ? h("p", {class: "sub"}, `Seen again as ${view.newer_record.id} ${relativeTime(view.newer_record.created_at)}; the case and plans stay on this record.`)
      : "");
}

// The in-flight plan, as one card that moves through stage, approve, run and
// re-scan in place.
function remediationPlanFlow(plan, view, {reload, diff}) {
  const s = plan.summary || {};
  const stage = planStageOf(plan);
  const you = plan.you || {};
  const resolved = view.resolution && !view.resolution.claim;
  const after = planRescan(plan, view);
  const stillThere = !resolved && after && after.outcome === "still_present";
  const failed = ["halted", "tampered", "stale", "blocked"].includes(stage)
    || ["failed", "partial"].includes((s.verification || {}).outcome) || Boolean(stillThere);
  const at = resolved ? 4 : stillThere ? 3 : {staged: 1, approved: 2, executed: 3, verified: 3, halted: 2}[stage] ?? 1;
  const ops = s.operations || [];
  const others = (s.findings || []).filter(fid => fid !== (view.finding || {}).id);
  const body = [];

  if (stage === "staged") {
    // Warnings stay in view above the approve control; the operations fold.
    const warnings = diff && !diff.error ? (diff.review || {}).warnings || [] : [];
    if (warnings.length) {
      body.push(h("div", {class: "remediation-warnings"},
        h("div", {class: "metric-k"}, "Before you approve"),
        h("ul", {class: "limitations"}, warnings.map(w => h("li", {}, w)))));
    }
    body.push(diff && !diff.error ? planDiffView(diff, {open: false, warnings: !warnings.length})
              : diff ? statusLine(unavailableReason(diff.error), "unknown") : "");
    const reason = textInput("", {placeholder: "Why this is right (required)", "data-focus": "approve"});
    reason.setAttribute("aria-label", "Reason for approving");
    const irreversible = ops.some(o => o.runnable && o.reversible === false);
    const typed = textInput("", {placeholder: `Type ${view.store_id} to confirm`});
    typed.setAttribute("aria-label", "Store id, to confirm an irreversible change");
    const approve = async () => {
      if (!reason.value.trim()) { toast("Say why it is right to approve. A bare approval is not recorded.", "err"); return; }
      try {
        const a = await api(`/actions/plans/${encodeURIComponent(plan.id)}/approve`, {method: "POST",
          body: JSON.stringify({reason: reason.value.trim(), typed_store_id: irreversible ? typed.value : ""})});
        toast(a.self_approved ? "Approved, recorded as self-approved. Run it next." : "Approved. Run it next.", "ok");
        await reload("run");
      } catch (e) { refused.replaceChildren(refusalLine(e, "Not approved")); }
    };
    const refused = h("div", {class: "refusal-slot"});
    body.push(!can("compliance")
      ? statusLine(`${roleNeed("compliance")} It is waiting in the Approval queue.`, "medium")
      : you.may_approve === false
      ? statusLine(you.needs_second_person
          ? `${you.reason || "A second person has to approve it."} It is waiting in the Approval queue.`
          : you.reason || "You cannot approve this plan.", "medium")
      : h("div", {class: "bar remediation-stage"},
          reason, irreversible ? typed : "",
          h("button", {class: "btn primary", type: "button", onclick: approve}, icon("check"), "Approve"),
          you.would_be_self_approval ? h("span", {class: "sub"}, "You staged it, so this is recorded as self-approved.") : ""),
      refused);
  } else if (stage === "approved") {
    const approval = (s.approvals || []).slice().sort((a, b) => String(b.approved_at || "").localeCompare(String(a.approved_at || "")))[0] || {};
    const mode = view.safe_mode || {};
    const run = async () => {
      try {
        const r = await api(`/actions/plans/${encodeURIComponent(plan.id)}/execute`, {method: "POST",
          body: JSON.stringify({approval_id: approval.id, verify: true})});
        const check = r.verification || {};
        toast(`${r.complete ? "Ran" : r.halted ? "Halted" : "Partially applied"}; read-back ${check.outcome || "not run"}. Re-scan next.`, r.complete ? "ok" : "err");
        await reload("rescan");
      } catch (e) { ranRefused.replaceChildren(refusalLine(e, "Not run")); }
    };
    const ranRefused = h("div", {class: "refusal-slot"});
    body.push(h("p", {class: "sub"}, `Approved by ${approval.approver || "?"} ${approval.approved_at ? relativeTime(approval.approved_at) : ""}`,
      approval.self_approved ? [" ", selfApprovedChip()] : "", approval.reason ? `: “${approval.reason}”` : ""));
    body.push(mode.safe_mode
      ? h("div", {class: "bar remediation-stage"},
          h("button", {class: "btn danger", type: "button", disabled: true, "data-focus": "run", title: mode.how_to_enable || ""}, icon("play"), "Run it"),
          h("span", {class: "sub"}, `Safe mode is on. Set ${mode.variable || "VECSHIELD_SAFE_MODE"}=0 on the server to run it.`))
      : can("compliance")
      ? h("div", {class: "bar remediation-stage"},
          h("button", {class: "btn danger", type: "button", "data-focus": "run", onclick: run}, icon("play"), "Run it"),
          h("span", {class: "sub"}, "Writes to the store now, then reads each change back."))
      : h("div", {class: "bar remediation-stage"},
          gated("compliance", h("button", {class: "btn danger", type: "button", "data-focus": "run"}, icon("play"), "Run it"))));
    body.push(ranRefused);
    if (diff && !diff.error) body.push(planDiffView(diff, {open: false}));
  } else {
    const latest = (s.executions || [])[0];
    if (latest && latest.halted) body.push(statusLine("The run halted before finishing; nothing after the failure ran.", "high"));
    if (stage === "tampered") body.push(statusLine("This plan no longer matches its hash and cannot be acted on. Stage a fresh one below.", "critical"));
    if (stage === "stale") body.push(statusLine("The store changed since this was staged. Stage it again below.", "medium"));
    if (s.verification) body.push(verificationBlock(s.verification));
    const expectation = ops.map(o => (view.executable || []).find(e => e.action === o.action))
      .filter(Boolean).map(e => e.rescan_text).find(Boolean);
    const expects = ops.map(o => (view.executable || []).find(e => e.action === o.action))
      .filter(Boolean).map(e => e.rescan_expect).find(Boolean);
    if (stillThere) {
      body.push(h("div", {class: "remediation-next"},
        statusLine(`Re-scan ${after.job_id || ""} still observes the finding` +
          (expects === "contains" ? ", as expected: this fix contains the exposure and leaves the data in place." : ".") +
          " Choose a fix that removes it below, or record a decision on the case.", "high"),
        h("div", {class: "bar remediation-stage"},
          h("button", {class: "btn", type: "button", "data-focus": "rescan",
                       onclick: () => goTo("findings", {finding: (view.finding || {}).id})}, icon("edit"), "Record a case decision"),
          view.rescan_supported && can("compliance")
            ? h("button", {class: "btn", type: "button", onclick: () => runRescan(view, "", reload)}, icon("refresh"), "Re-scan again")
            : "")));
    } else if (!resolved && !failed && ["executed", "verified"].includes(stage)) {
      body.push(h("div", {class: "remediation-next"},
        statusLine(`Next: re-scan to confirm. ${expectation || "A read-back confirms the change, not that the finding is gone."}`, "info"),
        view.rescan_supported
          ? h("div", {class: "bar remediation-stage"},
              gated("compliance", h("button", {class: "btn primary", type: "button", "data-focus": "rescan",
                           onclick: () => runRescan(view, "", reload)}, icon("refresh"), "Re-scan now")),
              can("compliance") ? h("span", {class: "sub"}, "Read-only; records a new run.") : "")
          : h("div", {class: "bar"},
              gated("operator", h("button", {class: "btn primary", type: "button", "data-focus": "rescan",
                           onclick: () => goTo("assess", {store: view.store_id})}, icon("play"), "Re-run the assessment")))));
    }
  }

  return h("section", {class: `remediation-card remediation-plan${failed ? " remediation-plan-failed" : ""}`,
                       "aria-labelledby": `plan-${plan.id}`},
    h("div", {class: "remediation-card-head"},
      h("h3", {class: "remediation-h", id: `plan-${plan.id}`}, ops.map(o => o.title).filter(Boolean).join(" · ") || "Plan"),
      h("button", {class: "link mono sub", type: "button", onclick: () => goTo("actions", {plan: plan.id}),
                   title: "Open this plan on its own page"}, plan.id)),
    h("div", {class: "remediation-plan-meta"},
      remediationStepper(at, {failed}),
      h("span", {class: "sub"}, `Staged by ${plan.staged_by || "?"} ${relativeTime(plan.staged_at)}`,
        ops.some(o => o.params && o.params.tenant_value) ? ` · tenant ${ops.find(o => o.params && o.params.tenant_value).params.tenant_value}` : "")),
    others.length ? h("p", {class: "sub"}, `This plan also fixes ${plural(others.length, "other finding")}; approving or running it covers them too.`) : "",
    body);
}

// The fixes for this finding as one choice, with the recommended one picked.
// While a plan is in flight the choice folds away under "Try a different fix".
function remediationChooser(view, {reload, secondary}) {
  const exec = view.executable || [];
  const guided = view.guided || [];
  const fid = (view.finding || {}).id || "finding";
  const options = [...exec.map(s => ({key: `x:${s.id}`, kind: "exec", item: s})),
                   ...guided.map(g => ({key: `g:${g.id}`, kind: "guided", item: g}))];
  const lead = options.find(o => o.kind === "exec" && o.item.supported !== false) || options[0];
  // After a fix ran and the finding is still there, the next pick is one that
  // has not been tried; the recommendation stays labelled where it was.
  const tried = new Set((view.plans || []).flatMap(p => ((p.summary || {}).operations || []).map(o => o.action)));
  const fresh = o => o.kind !== "exec" || (o.item.supported !== false && !tried.has(o.item.action));
  const untried = tried.size
    ? options.find(o => o.kind === "exec" && fresh(o) && o.item.rescan_expect === "clears") || options.find(fresh)
    : null;
  let chosen = (untried || lead || {}).key || "";
  const detail = h("div", {class: "remediation-detail", "aria-live": "polite"});
  const draw = () => {
    const o = options.find(x => x.key === chosen);
    detail.replaceChildren(!o ? "" : o.kind === "exec"
      ? remediationProposal(o.item, view, {reload})
      : remediationGuide(o.item, view, {reload}));
  };
  const radios = h("fieldset", {class: "remediation-options"},
    h("legend", {class: "sr-only"}, "Fixes for this finding"),
    options.map(o => {
      const s = o.item;
      const input = h("input", {type: "radio", name: `fix-${fid}`, value: o.key, checked: o.key === chosen,
                                onchange: () => { chosen = o.key; draw(); }});
      return h("label", {class: "remediation-option"}, input,
        h("span", {class: "remediation-option-text"},
          h("span", {class: "strong"}, s.title),
          h("span", {class: "remediation-chips"},
            o === lead ? stateChip("ok", "recommended", {glyph: "check"}) : "",
            o.kind === "exec"
              ? stateChip("info", "VecShield does it", {glyph: "shield"})
              : stateChip("unknown", "you do it", {glyph: "user"}),
            o.kind === "exec"
              ? (s.reversible ? stateChip("info", "reversible", {glyph: "refresh"}) : stateChip("critical", "cannot be undone"))
              : "",
            o.kind === "exec" && s.supported === false ? stateChip("unknown", "this store cannot") : "",
            o.kind === "exec" && s.supported !== false && s.supported !== true
              ? stateChip("unknown", "support not checked", {title: s.support_reason || "Whether this store can do it is checked when the fix is staged."})
              : "")));
    }));
  draw();
  const withheld = view.withheld || [];
  const content = [
    options.length ? radios : "",
    detail,
    withheld.length
      ? h("details", {class: "remediation-withheld"},
          h("summary", {}, `Withheld (${number(withheld.length)}): not offered on this evidence`),
          h("ul", {class: "limitations"}, withheld.map(w => h("li", {},
            h("span", {class: "strong"}, w.title || w.action), ": ", w.reason))))
      : "",
  ];
  if (secondary) {
    return h("details", {class: "remediation-section remediation-more"},
      h("summary", {}, `Try a different fix (${number(options.length)})`), ...content);
  }
  return h("section", {class: "remediation-section", "aria-labelledby": "remediation-choose"},
    h("h3", {class: "remediation-h", id: "remediation-choose"}, "Choose a fix"), ...content);
}

function remediationProposal(s, view, {reload}) {
  const inputs = {};
  const note = textInput("", {placeholder: "Why (optional)"});
  note.setAttribute("aria-label", `Reason for staging: ${s.title}`);
  const blocked = s.supported === false;
  const hintLists = [];
  const fields = [];
  for (const name of s.needs_params || []) {
    const label = name === "tenant_value" ? `Tenant to assign (${(s.params || {}).tenant_field || "tenant field"})` : name.replace(/_/g, " ");
    const hints = (s.param_hints || {})[name] || [];
    const listId = `hints-${s.id}-${name}`;
    inputs[name] = textInput("", {placeholder: hints.length ? `e.g. ${hints[0]}` : name === "tenant_value" ? "e.g. acme" : "",
                                  list: hints.length ? listId : null, "data-focus": "param"});
    inputs[name].setAttribute("aria-label", label);
    fields.push(h("label", {class: "remediation-param"}, h("span", {class: "sub"}, label,
      hints.length ? `: recorded ${hints.join(", ")}` : ""), inputs[name]));
    if (hints.length) hintLists.push(h("datalist", {id: listId}, hints.map(v => h("option", {value: v}))));
  }
  async function stageIt() {
    const params = {...(s.params || {})};
    for (const [name, input] of Object.entries(inputs)) {
      if (!String(input.value || "").trim()) {
        toast(`${name === "tenant_value" ? "The tenant to assign" : name.replace(/_/g, " ")} is needed to stage this.`, "err");
        input.focus?.();
        return;
      }
      params[name] = String(input.value).trim();
    }
    try {
      const plan = await api(`/stores/${encodeURIComponent(view.store_id)}/actions/plans`, {
        method: "POST",
        body: JSON.stringify({suggestions: [{...s, params}], note: note.value || `Fix for ${s.finding_id}`}),
      });
      const blocked = blockedOperations(plan);
      toast(blocked.length ? `Staged ${plan.id}, but it cannot run: ${blocked[0].support_reason || "blocked"}`
                           : `Staged ${plan.id}. Approve it next.`,
            blocked.length ? "err" : "ok");
      await reload("approve");
    } catch (e) { refused.replaceChildren(refusalLine(e, "Not staged")); }
  }
  const refused = h("div", {class: "refusal-slot"});
  const risk = String(s.risk || "low");
  return h("article", {class: `remediation-card${blocked ? " remediation-card-blocked" : ""}`},
    s.rationale ? h("p", {class: "sub"}, s.rationale) : "",
    factList([
      ["What changes", s.effect],
      ["Reaches", capitalize(reachText(s))],
      ["Reversible?", s.reversible ? `Yes. ${s.undo || ""}` : `No. ${s.undo || "It cannot be undone."}`],
      ["Verified by", [s.verification, s.rescan_text].filter(Boolean).join(" Then: ")],
      ["Does not", s.caveat],
    ], {className: "kv remediation-kv", ddClass: "", skipEmpty: true}),
    h("div", {class: "remediation-chips"}, stateChip(RISK_TONE[risk] || "info", `${risk} risk`), basisChip(s),
      (s.rests_on || []).length ? h("span", {class: "sub mono"}, s.rests_on.join(", ")) : ""),
    excludedList(s),
    blocked
      ? statusLine(`This store cannot do it: ${s.support_reason}`, "unknown")
      : s.supported === true ? "" : statusLine(s.support_reason || "Whether this store can do it is checked when it is staged.", "info"),
    hintLists,
    can("compliance")
      ? h("div", {class: "bar remediation-stage"},
          fields, note,
          h("button", {class: "btn primary", type: "button", disabled: blocked, onclick: stageIt},
            icon("play"), "Stage this fix"))
      : h("div", {class: "bar remediation-stage"},
          gated("compliance", h("button", {class: "btn primary", type: "button"}, icon("play"), "Stage this fix"))),
    refused);
}

function remediationGuide(g, view, {reload}) {
  const note = textInput("", {placeholder: "What you changed (optional)"});
  note.setAttribute("aria-label", `What was changed: ${g.title}`);
  async function markDone({thenRescan = false} = {}) {
    try {
      const r = await api(`/admin/findings/${encodeURIComponent(g.finding_id)}/remediation/attest`, {
        method: "POST", body: JSON.stringify({guided_id: g.id, note: note.value || ""}),
      });
      if (!thenRescan) {
        toast(r.note || "Recorded as a claim.", "ok");
        await reload("rescan");
        return;
      }
    } catch (e) { refused.replaceChildren(refusalLine(e, "Not recorded")); return; }
    await runRescan(view, g.id, reload);
  }
  // The last catalogued step is always "mark it done here, then re-scan";
  // the buttons below say that, so the list does not.
  const steps = (g.steps || []).filter(step => !/^Mark this done here/.test(step));
  const attested = g.attested;
  const refused = h("div", {class: "refusal-slot"});
  return h("article", {class: "remediation-card remediation-guided"},
    g.summary ? h("p", {class: "sub"}, g.summary) : "",
    h("ol", {class: "remediation-procedure"}, steps.map(step => h("li", {}, step))),
    (g.settings || []).length
      ? table(["Where", "Setting", "Value"], g.settings.map(x => h("tr", {},
          h("td", {}, x.where),
          h("td", {}, h("code", {class: "remediation-code"}, x.key)),
          h("td", {}, h("code", {class: "remediation-code"}, x.value),
            x.note ? h("div", {class: "sub"}, x.note) : ""))))
      : "",
    h("dl", {class: "kv remediation-kv"},
      h("dt", {}, "Who"), h("dd", {}, g.owner || "unassigned", g.risk ? ` · ${g.risk} risk` : ""),
      h("dt", {}, "Why you"), h("dd", {}, g.not_executable_because || "-"),
      h("dt", {}, "Verified by"), h("dd", {}, g.verify || "A new assessment."),
      g.undo ? [h("dt", {}, "Undo"), h("dd", {}, g.undo)] : ""),
    attested ? guidedClaimLine(g, attested, view) : "",
    h("div", {class: "bar remediation-stage"},
      g.link ? h("button", {class: "btn", type: "button", onclick: () => goTo(g.link.view, g.link.params || {})},
        g.link.label || "Open") : "",
      can("compliance") ? note : "",
      gated("compliance", g.rescan_supported
        ? h("button", {class: "btn primary", type: "button", onclick: () => markDone({thenRescan: true})},
            icon("check"), attested ? "Mark done again and re-scan" : "Mark done and re-scan")
        : h("button", {class: "btn primary", type: "button", onclick: () => markDone()},
            icon("check"), attested ? "Mark done again" : "Mark done")),
      can("compliance") ? h("span", {class: "sub"}, g.rescan_supported
        ? "Marking it done records a claim; only the re-scan verifies it."
        : "Marking it done records a claim; a new assessment verifies it.") : ""),
    refused);
}

function guidedClaimLine(g, attested, view) {
  const said = `Marked done by ${attested.actor} ${relativeTime(new Date(attested.at * 1000).toISOString())}` +
    (attested.note ? `: \u201c${attested.note}\u201d` : "");
  const after = rescanSince(view, attested.at);
  if (after && after.outcome === "still_present") {
    return h("div", {class: "remediation-next"},
      statusLine(`${said}. The re-scan after it still observes the finding, so the claim did not hold ` +
        "and the case is back in progress.", "high"),
      h("div", {class: "bar"}, h("button", {class: "btn small", type: "button",
        onclick: () => goTo("findings", {finding: (view.finding || {}).id})}, icon("edit"), "Record a case decision")));
  }
  if (after && after.outcome === "resolved") return statusLine(`${said}. A re-scan confirmed it.`, "ok");
  return statusLine(`${said}. A claim until a re-scan confirms it.`, "info");
}

async function runRescan(view, guidedId, reload) {
  const id = (view.finding || {}).id;
  toast("Re-running the check, read-only.", "ok");
  try {
    const r = await api(`/admin/findings/${encodeURIComponent(id)}/remediation/verify`, {
      method: "POST", body: JSON.stringify({guided_id: guidedId || ""}),
    });
    toast(`Re-scan: ${RESCAN_LABEL[r.outcome] || r.outcome}` +
          (r.case && r.case.state === "verified" ? ". The case is verified by this run." :
           r.case && r.case.state === "in_progress" && r.outcome === "still_present" ? ". The case is back in progress." : "."),
          r.outcome === "resolved" ? "ok" : "err");
    await reload("rescan-result");
  } catch (e) { toast(e.status === 403 ? refusalText(e) : e.message, "err"); }
}

function remediationRescans(view, {reload}) {
  const rows = (view.rescans || []).slice().reverse();
  const last = rows[0];
  return h("section", {class: "remediation-section", "aria-labelledby": "remediation-verify-h"},
    h("h3", {class: "remediation-h", id: "remediation-verify-h"}, "Verify by re-scan"),
    view.rescan_supported
      ? h("p", {class: "sub"}, "Re-runs the check behind this finding, read-only. Resolved needs a complete run; " +
          "a partial one is inconclusive however clean it looks.")
      : statusLine("This finding is re-checked by a full assessment, not from here.", "info"),
    last
      ? h("div", {class: "remediation-last", tabindex: "-1", "data-focus": "rescan-result"},
          stateChip(RESCAN_TONE[last.outcome] || "unknown", RESCAN_LABEL[last.outcome] || last.outcome),
          " ", h("span", {class: "sub"}, `${relativeTime(new Date(last.at * 1000).toISOString())} by ${last.actor}`),
          last.job_id ? [" · ", h("button", {class: "link mono", type: "button",
            onclick: () => goTo("history", {scan: last.job_id})}, last.job_id)] : "",
          last.reason ? h("p", {class: "sub"}, last.reason) : "")
      : view.rescan_supported ? statusLine("Not re-scanned from here yet.", "info") : "",
    rows.length > 1
      ? h("details", {class: "evidence-data"},
          h("summary", {}, `Earlier re-scans (${number(rows.length - 1)})`),
          h("ul", {class: "limitations"}, rows.slice(1).map(r => h("li", {},
            stateChip(RESCAN_TONE[r.outcome] || "unknown", RESCAN_LABEL[r.outcome] || r.outcome), " ",
            h("span", {class: "sub"}, `${formatWhen(new Date(r.at * 1000).toISOString())} · ${r.actor} · `),
            h("span", {class: "mono sub"}, r.job_id || "-")))))
      : "",
    view.rescan_supported
      ? h("div", {class: "bar"},
          gated("compliance", h("button", {class: "btn", type: "button", onclick: () => runRescan(view, "", reload)},
            icon("refresh"), "Re-scan now")))
      : h("div", {class: "bar"},
          gated("operator", h("button", {class: "btn", type: "button", onclick: () => goTo("assess", {store: view.store_id})},
            icon("play"), "Run an assessment"))));
}

// A line shown once at the top of a screen after it redraws, saying what the
// reader just did. It is announced through the page's live region rather than
// a toast (§4B.5), and survives the redraw that follows a save.
let exceptionsFlash = "";

async function renderExceptions() {
  await loadCore();
  const X = COMPLIANCE_COPY.exceptions;
  const box = h("div", {});
  box.append(pageHeader("exceptions", X.header,
    gated("compliance", h("button", {class: "btn primary", type: "button", onclick: () => requestExceptionModal()},
      icon("plus"), "Request exception"))));
  const out = h("div", {});
  box.append(out);
  out.replaceChildren(loadingState("Loading exceptions"));
  try {
    const body = await api("/compliance/exceptions");
    await approvalsPolicy();
    // Titles, not ids, lead each row. Best-effort: ids still work without it.
    try { await loadPack(); } catch { /* the id is shown instead */ }
    const items = body.exceptions || [];
    const soon = items.filter(e => e.status === "active" && e.expires_at &&
      (toMillis(e.expires_at) - Date.now()) < 30 * 86400000).length;
    const flash = exceptionsFlash;
    exceptionsFlash = "";
    out.replaceChildren(
      pageIntro("exceptions", {
        facts: [
          [X.pending, number(body.pending_approval), X.pendingNote],
          [X.active, number(body.active),
           soon ? `${X.activeNote} · ${countText(soon, X.lapse)}` : X.activeNote],
          [X.expired, number(body.expired), X.expiredNote],
        ],
        steps: [
          X.steps[0],
          fillCopy(X.steps[1], {approver: approverSentence("it")}),
          X.steps[2],
        ],
        actions: [
          introAction("See the criteria these cover", "check", () => goTo("criteria")),
          introAction("Findings behind the gaps", "alert", () => goTo("findings")),
        ],
      }),
      flash ? statusLine(flash, "ok", {live: true}) : "",
      panel("Exceptions", items.length
        ? h("div", {},
            statusLine(body.note || "", "medium"),
            exceptionsTable(items))
        : emptyState(X.empty)));
  } catch (e) {
    out.replaceChildren(panel("Exceptions", e.status === 409
      ? unavailableState(unavailableReason(e), "Exceptions are stored with scan history.")
      : errorState(unavailableReason(e), () => route())));
  }
  return box;
}

// Who approved an exception and why. The reason is what the server stored for
// the approval (C-8); a record from before reasons were required says so.
function approvalReasonOf(e) {
  return e.approval_reason || e.approve_reason || e.approved_reason ||
    (e.approval && typeof e.approval === "object" ? e.approval.reason : "") || "";
}

function exceptionsTable(items) {
  const X = COMPLIANCE_COPY.exceptions;
  const rows = items.map(e => {
    const c = packCriterion(e.criterion_id);
    const reason = approvalReasonOf(e);
    const actions = h("td", {});
    const row = h("tr", {dataset: {exception: e.id || ""}},
      h("td", {},
        h("button", {class: "link", type: "button",
          title: "Open this criterion for the exception's store",
          onclick: () => goTo("criteria", {store: e.scope, framework: frameworkOfCriterion(e.criterion_id),
                                           criterion: e.criterion_id})},
          criterionTitle(c, e.criterion_id)),
        criterionTitle(c, e.criterion_id) !== e.criterion_id ? h("div", {class: "sub mono"}, e.criterion_id) : ""),
      h("td", {}, e.scope),
      h("td", {}, exceptionChip(e.status),
        h("div", {class: "sub"}, e.approved_by ? fillCopy(X.approvedBy, {who: e.approved_by})
                                               : fillCopy(X.requestedBy, {who: e.requested_by})),
        e.approved_by
          ? h("div", {class: reason ? "exc-reason" : "sub"},
              reason ? fillCopy(X.approvalReason, {text: reason}) : X.noApprovalReason)
          : "",
        e.self_approved ? h("div", {}, selfApprovedChip()) : ""),
      h("td", {}, e.expires_at ? formatWhen(e.expires_at) : "-"),
      h("td", {}, e.rationale),
      actions);
    // Approval opens a reason field in the row below; revoking is offered
    // only where it changes something: a pending or active exception.
    const formRow = h("tr", {class: "exc-approve-row", hidden: true},
      h("td", {colspan: String(X.columns.length)}));
    const approve = e.status === "pending_approval"
      ? h("button", {class: "btn small", type: "button", "aria-expanded": "false",
                     onclick: () => toggleApprove()}, COMPLIANCE_COPY.forms.approve.open)
      : "";
    function toggleApprove() {
      const opening = formRow.hidden;
      formRow.hidden = !opening;
      approve.setAttribute("aria-expanded", String(opening));
      if (!opening) { formRow.firstChild.replaceChildren(); approve.focus?.(); return; }
      const form = approveExceptionForm(e, {close: () => toggleApprove()});
      formRow.firstChild.replaceChildren(form);
      form.querySelector?.("textarea")?.focus?.();
    }
    if (can("compliance")) {
      actions.append(rowActions(approve,
        ["active", "pending_approval"].includes(e.status)
          ? [{label: "Revoke", glyph: "trash", danger: true, onclick: () => decideException(e.id, "revoke", e)}]
          : []));
    }
    return [row, formRow];
  });
  // The form row spans every column, so it takes no column name; nor does
  // the unnamed actions column (its head reads "Actions" to a screen reader).
  return table(X.columns, rows.flat(), {tableClass: "exc-table"});
}

// The one chip for an exception's state, on the Exceptions table and in the
// criterion detail alike.
function exceptionChip(status, {long = false} = {}) {
  const meta = complianceLabel("exceptionStatus", status);
  return stateChip(meta.tone, long ? (meta.chip || meta.text) : meta.text, {title: meta.help || ""});
}

// Approving needs a reason (D-C6, C-8): it is sent with the approval, the
// server refuses one without it, and the table shows it afterwards.
function approveExceptionForm(e, {close}) {
  const F = COMPLIANCE_COPY.forms.approve;
  const reason = h("textarea", {required: true, maxlength: "2000", rows: "2"});
  const f = hintField(F.reason, reason, F.reasonHint);
  return inlineForm({
    title: F.heading,
    intro: [approverSentence("it")],
    body: [f],
    submitLabel: F.submit,
    onCancel: close,
    onSubmit: async () => {
      if (f.fail(reason.value.trim() ? "" : F.needReason)) { reason.focus?.(); return; }
      await api(`/compliance/exceptions/${encodeURIComponent(e.id)}/approve`,
                {method: "POST", body: JSON.stringify({reason: reason.value.trim()})});
      exceptionsFlash = F.done;
      announce(F.done);
      route();
    },
  });
}

// The framework a criterion belongs to, from the pack if it has been read,
// else from the id's prefix (HIPAA-…, GDPR-…), else nothing.
function frameworkOfCriterion(criterionId) {
  const hit = (state.pack?.criteria || []).find(c => c.criterion_id === criterionId);
  if (hit) return hit.framework;
  const prefix = String(criterionId || "").split("-")[0].toUpperCase();
  return {HIPAA: "HIPAA", GDPR: "GDPR", CCPA: "CCPA/CPRA", PCI: "PCI-DSS", SOC2: "SOC 2",
          AIACT: "EU AI Act"}[prefix] || "";
}

function exceptionTone(status) {
  return complianceLabel("exceptionStatus", status).tone;
}

// Revoking reopens the gap the exception covered, at once, so it asks first.
// Approving is not here: it needs a reason, which its inline form collects.
async function decideException(id, action, exception = null) {
  const X = COMPLIANCE_COPY.exceptions;
  if (action !== "revoke") return;
  const ok = await confirmAction({
    title: X.revokeTitle,
    message: fillCopy(X.revokeMessage, {
      criterion: criterionTitle(packCriterion(exception?.criterion_id), exception?.criterion_id || "The criterion"),
      scope: exception?.scope || "its store"}),
    confirmLabel: X.revokeConfirm, danger: true,
  });
  if (!ok) return;
  try {
    await api(`/compliance/exceptions/${encodeURIComponent(id)}/revoke`, {method: "POST"});
    exceptionsFlash = COMPLIANCE_COPY.forms.approve.revoked;
    announce(exceptionsFlash);
    route();
  } catch (e) {
    toast(e.status === 403 ? refusalText(e) : e.message, "err");
  }
}

// Pick lists, not typed ids: the criterion comes from the pack and the scope
// from the registered stores. Opened from a criterion, both are filled in.
async function requestExceptionModal({criterion: preset = "", scope: presetScope = ""} = {}) {
  const criterion = selectInput([[preset, preset || "Loading criteria…"]], preset,
                                {"aria-label": "Criterion", required: true});
  const scope = selectInput(storeOptions(["", "Choose a store"]), presetScope,
                            {"aria-label": "Store", required: true});
  const rationale = h("textarea", {required: true, placeholder: "Why this gap is acceptable for now, and what makes up for it"});
  const expires = textInput("", {type: "date", required: true});
  modal("Request an exception", h("div", {},
    statusLine(`${COMPLIANCE_COPY.exceptions.requestNote} ${approverSentence("it")}`, "medium"),
    field("Criterion", criterion), field("Store", scope),
    field("Reason", rationale), field("Ends on", expires)),
    async () => {
      if (!criterion.value || !scope.value) throw new Error("Choose a criterion and a store.");
      await api("/compliance/exceptions", {method: "POST", body: JSON.stringify({
        criterion_id: criterion.value, scope: scope.value,
        rationale: rationale.value,
        expires_at: expires.value ? `${expires.value}T00:00:00+00:00` : "",
      })});
      toast("Exception requested.");
      closeModal();
      route();
    }, "Request");
  try {
    const pack = await loadPack();
    criterion.replaceChildren(...[["", "Choose a criterion"],
      ...(pack.criteria || []).map(c => [c.criterion_id, `${criterionTitle(c)} (${c.criterion_id})`])]
      .map(([value, label]) => h("option", {value, selected: value === preset}, label)));
    criterion.value = preset;
  } catch (e) {
    if (!preset) criterion.replaceChildren(h("option", {value: ""}, `The criteria could not be read: ${unavailableReason(e)}`));
  }
}

// ------------------------------------------------------------ inline forms ---
// The criterion's writes open in place, under the button that opened them,
// instead of in a dialog (§4B.3, C-4). Each has a heading, visible labels,
// errors tied to their fields, one role=status line for what happened, and
// Cancel returns focus to the opener. Destructive confirmations stay dialogs.
let inlineFormSeq = 0;

function inlineForm({title, intro = [], body = [], submitLabel, onSubmit, onCancel}) {
  const id = `inline-form-${++inlineFormSeq}`;
  const status = h("p", {class: "inline-status", id: `${id}-status`, role: "status", tabindex: "-1"});
  const submit = h("button", {class: "btn small primary", type: "submit"}, submitLabel);
  const cancel = h("button", {class: "btn small", type: "button", onclick: () => onCancel?.()},
                   COMPLIANCE_COPY.forms.cancel);
  const form = h("form", {class: "inline-form", "aria-labelledby": `${id}-h`, novalidate: "novalidate",
    onsubmit: async event => {
      event?.preventDefault?.();
      if (submit.disabled) return;
      submit.disabled = true;
      status.textContent = "";
      status.classList.remove("is-error");
      try {
        await onSubmit({status});
      } catch (e) {
        status.textContent = e?.status === 403 ? refusalText(e) : (e?.message || String(e));
        status.classList.add("is-error");
        status.focus?.();
      } finally {
        submit.disabled = false;
      }
    }},
    h("h4", {class: "inline-form-h", id: `${id}-h`}, title),
    intro.filter(Boolean).map(text => h("p", {class: "inline-intro"}, text)),
    body,
    status,
    h("div", {class: "bar inline-actions"}, submit, cancel));
  return form;
}

// A group of radio buttons with a legend, a hint per option, and an error tied
// to the group. `.value` reads the chosen option; `.fail(msg)` shows an error.
let choiceSeq = 0;
function choiceGroup(legend, options, value = "", {hint = "", disabled = false} = {}) {
  const id = `choice-${++choiceSeq}`;
  const err = h("span", {class: "field-error", id: `${id}-err`, hidden: true});
  const hintNode = hint ? h("span", {class: "field-hint", id: `${id}-hint`}, hint) : "";
  const inputs = options.map(([key, label, help]) => h("input", {type: "radio", name: id, value: key,
    checked: key === value, disabled, "aria-describedby": help ? `${id}-${key}-help` : null}));
  const group = h("fieldset", {class: "choice-group", "aria-describedby": [hint ? `${id}-hint` : "", `${id}-err`].filter(Boolean).join(" ")},
    h("legend", {}, legend),
    hintNode,
    h("div", {class: "choice-options"}, options.map(([key, label, help], index) =>
      h("label", {class: "choice"}, inputs[index],
        h("span", {class: "choice-text"}, h("span", {class: "choice-label"}, label),
          help ? h("span", {class: "sub", id: `${id}-${key}-help`}, help) : "")))),
    err);
  Object.defineProperty(group, "value", {get: () => inputs.find(i => i.checked)?.value || ""});
  group.inputs = inputs;
  group.fail = message => {
    err.textContent = message || "";
    err.hidden = !message;
    if (message) group.setAttribute("aria-invalid", "true");
    else group.removeAttribute("aria-invalid");
    return Boolean(message);
  };
  group.focus = () => (inputs.find(i => i.checked) || inputs[0])?.focus?.();
  return group;
}

// Record a reviewer's decision (was a dialog). The three choices say what each
// one means, and the reason is required.
function decisionForm(a, {auditId, store, close, done}) {
  const F = COMPLIANCE_COPY.forms.decision;
  const conclusion = choiceGroup(F.conclusion, ["satisfied", "gap", "not_applicable"].map(key =>
    [key, complianceLabel("conclusion", key).text, complianceLabel("conclusion", key).help]));
  const rationale = h("textarea", {required: true, maxlength: "4000", rows: "3"});
  const period = textInput("", {placeholder: "2026-Q3"});
  const fr = hintField(F.rationale, rationale, F.rationaleHint);
  const fp = hintField(F.period, period, F.periodHint);
  return inlineForm({
    title: F.heading,
    intro: [F.intro[0],
            fillCopy(F.intro[1], {audit: auditId ? fillCopy(F.thisAudit, {audit: auditId}) : F.latestAudit}),
            F.intro[2]],
    body: [conclusion, fr, fp],
    submitLabel: F.submit,
    onCancel: close,
    onSubmit: async () => {
      const bad = [conclusion.fail(conclusion.value ? "" : F.needConclusion),
                   fr.fail(rationale.value.trim() ? "" : F.needRationale)];
      if (bad[0]) { conclusion.focus(); return; }
      if (bad[1]) { rationale.focus?.(); return; }
      const body = {conclusion: conclusion.value, rationale: rationale.value.trim(), period: period.value.trim()};
      if (auditId) body.audit_id = auditId;
      const r = await api(`/stores/${encodeURIComponent(store)}/criteria/${encodeURIComponent(a.criterion_id)}/decision`,
                          {method: "POST", body: JSON.stringify(body)});
      done(fillCopy(F.saved, {who: (r?.decision || {}).reviewer || "you"}));
    },
  });
}

// Answer this criterion's questions (was a dialog). Answers are stored per
// store and apply to every criterion that shares the question; the full
// questionnaire asks each one once (C-3).
function answersForm(a, {store, close, done}) {
  const F = COMPLIANCE_COPY.forms.answers;
  const questions = Object.keys(a.applicability || {});
  const options = Object.entries(COMPLIANCE_COPY.questionnaire.options);
  const controls = questions.map(question => {
    const meta = (state.pack?.applicability_questions || {})[question] || {};
    const who = h("span", {class: "sub choice-who"}, "");
    const group = choiceGroup(questionText(question), options.map(([key, label]) => [key, label, ""]),
                              a.applicability[question] || "requires_confirmation", {hint: meta.help || ""});
    group.append(who);
    return {question, group, who};
  });
  const readNote = h("div", {});
  const form = inlineForm({
    title: F.heading,
    intro: [fillCopy(F.intro, {store: store || "this store"})],
    body: [readNote, ...controls.map(c => c.group),
           h("button", {class: "link", type: "button", onclick: () => goTo("criteria", {answers: "1", store})},
             icon("list"), COMPLIANCE_COPY.questionnaire.open)],
    submitLabel: F.submit,
    onCancel: close,
    onSubmit: async () => {
      if (!store) throw new Error(F.needStore);
      const answers = {};
      for (const c of controls) answers[c.question] = c.group.value || "requires_confirmation";
      await api(`/stores/${encodeURIComponent(store)}/applicability`,
                {method: "POST", body: JSON.stringify({answers})});
      done(fillCopy(F.saved, {store}));
    },
  });
  if (store) {
    api(`/stores/${encodeURIComponent(store)}/applicability`).then(stored => {
      for (const c of controls) {
        const row = (stored.answers || {})[c.question];
        c.who.textContent = row
          ? fillCopy(F.who, {answer: complianceLabel("applicabilityAnswer", row.answer).text,
                             who: row.answered_by || "someone", when: relativeTime(row.answered_at)})
          : F.nobody;
      }
    }).catch(e => {
      readNote.replaceChildren(statusLine(fillCopy(F.readFailed, {why: unavailableReason(e)}), "medium"));
    });
  }
  return form;
}

const SHA256_INLINE = /^(sha256:)?[0-9a-f]{64}$/i;

// Add a document for review (was a dialog that sent people to another screen
// to register one first). Either pick one already added, or add a new one
// here: it is registered and sent for review in one step, and the criterion
// stays on screen.
function attachForm(a, {store, close, done}) {
  const F = COMPLIANCE_COPY.forms.attach;
  const conditional = new Set(a.fallback_required || []);
  const needs = a.missing_evidence || [];
  const requirement = selectInput(needs.map(name => [name, conditional.has(name)
    ? fillCopy(F.conditional, {name: evidenceName(name)}) : evidenceName(name)]), needs[0] || "");
  const about = h("div", {class: "ev-req-about"});
  const describe = () => {
    const info = evidenceInfo(requirement.value);
    about.replaceChildren(
      info.what ? h("p", {class: "sub"}, info.what) : "",
      (info.examples || []).length ? h("p", {class: "sub"}, fillCopy(F.example, {text: info.examples.join("; ")})) : "",
      info.reviewer_checks ? h("p", {class: "sub"}, fillCopy(F.reviewerChecks, {text: info.reviewer_checks})) : "");
  };
  requirement.addEventListener("change", describe);
  describe();

  const source = choiceGroup(F.source, [["existing", F.existing, ""], ["new", F.fresh, ""]], "existing");
  const doc = selectInput([["", F.loading]], "", {required: true});
  const title = textInput("", {maxlength: "300"});
  const hash = textInput("", {spellcheck: "false", placeholder: "64 hex characters"});
  const from = textInput("", {type: "date"});
  const to = textInput("", {type: "date"});
  const period = textInput("", {placeholder: "2026-Q3"});
  const f = {
    requirement: hintField(F.need, requirement, ""),
    doc: hintField(F.document, doc, ""),
    title: hintField(F.title, title, F.titleHint),
    hash: hintField(F.hash, hash, F.hashHint),
    from: hintField(F.from, from, ""),
    to: hintField(F.to, to, ""),
    period: hintField(F.period, period, F.periodHint),
  };
  const existingBox = h("div", {class: "inline-branch", dataset: {branch: "existing"}}, f.doc);
  const newBox = h("div", {class: "inline-branch", dataset: {branch: "new"}, hidden: true},
    f.title, f.hash, h("div", {class: "ev-form-pair"}, f.from, f.to));
  const sync = () => {
    const fresh = source.value === "new";
    existingBox.hidden = fresh;
    newBox.hidden = !fresh;
  };
  for (const input of source.inputs) input.addEventListener("change", sync);

  const form = inlineForm({
    title: F.heading,
    intro: [F.intro],
    body: [f.requirement, about, source, existingBox, newBox, f.period],
    submitLabel: F.submit,
    onCancel: close,
    onSubmit: async () => {
      const review = artifactId => api("/compliance/reviews", {method: "POST", body: JSON.stringify({
        artifact_id: artifactId, criterion_id: a.criterion_id, requirement: requirement.value,
        scope: store, period: period.value.trim()})});
      if (source.value !== "new") {
        if (f.doc.fail(doc.value ? "" : F.needDocument)) { doc.focus?.(); return; }
        await review(doc.value);
        done(F.sent);
        return;
      }
      const bad = [
        f.title.fail(title.value.trim() ? "" : F.needTitle),
        f.hash.fail(!hash.value.trim() || SHA256_INLINE.test(hash.value.trim()) ? "" : F.badHash),
        f.to.fail(from.value && to.value && to.value < from.value ? F.badPeriod : ""),
      ];
      if (bad.some(Boolean)) { [title, hash, to][bad.findIndex(Boolean)].focus?.(); return; }
      const created = await api("/compliance/evidence", {method: "POST", body: JSON.stringify({
        title: title.value.trim(), scope: store, content_hash: hash.value.trim() || null,
        period_start: from.value || null, period_end: to.value || null, supersedes: null, note: ""})});
      try {
        await review(created?.id);
      } catch (e) {
        // The document exists now; only the review failed. Say so rather than
        // leave someone to add it twice.
        throw new Error(`The document was added, but sending it for review failed: ${e.message || e}`);
      }
      done(F.sentNew);
    },
  });
  api("/compliance/evidence").then(body => {
    const usable = (body.artifacts || []).filter(x => x.usable !== false);
    doc.replaceChildren(...[["", usable.length ? F.choose : F.noneUsable],
      ...usable.map(x => [x.id, `${x.title}${x.scope ? ` · ${x.scope}` : ""}`])]
      .map(([value, label]) => h("option", {value}, label)));
    if (!usable.length) {
      for (const input of source.inputs) input.checked = input.value === "new";
      sync();
    }
  }).catch(e => {
    doc.replaceChildren(h("option", {value: ""}, fillCopy(F.readFailed, {why: unavailableReason(e)})));
  });
  return form;
}

// Moves focus into a form that just opened, at its first field.
function focusFirstField(form) {
  const first = form.querySelector?.("input:not([type=hidden]):not([disabled]), select, textarea");
  (first || form.querySelector?.("button"))?.focus?.();
}

// ------------------------------------------------------------ criteria page ---
// A criterion leads with what it asks, in words, and keeps its id small. The
// words come from the pack (title, paraphrase) and the pack's vocabulary
// (artifact types, applicability questions), served by /compliance/criteria;
// an identifier the vocabulary does not explain is made readable, never
// printed raw.

function evidenceInfo(name) {
  return (state.pack?.evidence_types || {})[name] ||
    {label: String(name || "").replace(/_/g, " "), what: "", examples: [], reviewer_checks: ""};
}

function questionText(key) {
  return ((state.pack?.applicability_questions || {})[key] || {}).question || String(key || "").replace(/_/g, " ");
}

function packCriterion(id) {
  return (state.pack?.criteria || []).find(c => c.criterion_id === id) || null;
}

function criterionTitle(c, id = "") {
  return (c && c.title) || (c && c.criterion_id) || id;
}

function citationOf(c) {
  const src = (c?.sources || [])[0];
  return src ? (src.citation || src.section || src.title || "") : "";
}

// What each status means, beside the state itself.
const CRITERION_STATUS_HELP = Object.fromEntries(
  Object.entries(COMPLIANCE_COPY.labels.criterionStatus).map(([key, meta]) => [key, meta.help]));

// ------------------------------------------------------------ plain / legal ---
// Two layers (§4B.2): what an obligation means for you, in plain words, and
// one disclosure away its legal wording and source. `copy.plain` is the
// pack's reviewed plain wording once the pack carries one (D-C4); until then
// the title stands in. `source.mapping` (the mapping-status line) stays in
// view under the disclosure, never inside it.
function plainLegal(copy = {}, source = {}) {
  const P = COMPLIANCE_COPY.plainLegal;
  const plain = copy.plain || copy.title || "";
  return h("div", {class: "plain-legal"},
    h("div", {class: "crit-section-k"}, P.heading),
    plain ? h("p", {class: "plain-legal-text"}, plain) : "",
    h("details", {class: "plain-legal-more"},
      h("summary", {}, icon("file"), P.legal),
      h("div", {class: "plain-legal-body"},
        h("p", {class: "crit-asks-text"}, copy.legal || P.noWording),
        (source.tags || []).length ? h("div", {class: "tag-row"}, source.tags) : "",
        ...(source.extra || []))),
    source.mapping || "");
}

// ------------------------------------------------------------ mapping line ---
// Whether a mapping has been legally reviewed (§4B.4, C-7). One neutral line
// with a document icon, never green and never a check mark, under every
// framework header, criterion citation and template. It reads whatever
// lifecycle and review fields the pack serves: today the pack says "draft"
// with no review; a ContentReview record, when the server adds one, names the
// reviewer and date. A lifecycle that claims review without a record says so.
function reviewRecordOf(subject) {
  if (!subject || typeof subject !== "object") return null;
  const last = list => (Array.isArray(list) && list.length ? list[list.length - 1] : null);
  // `regulatory_review` was null, may become a list, and is never printed raw.
  const review = subject.regulatory_review;
  const record = subject.content_review ||
    last(subject.content_reviews) || last(subject.reviews) ||
    (Array.isArray(review) ? last(review) : review && typeof review === "object" ? review : null);
  return record && typeof record === "object" ? record : null;
}

// States at or past legal review: only these may borrow the pack's review
// records. A draft pack with one reviewed slice is still a draft.
const REVIEWED_STATES = new Set(["regulatory_reviewed", "pilot", "published"]);

function reviewDay(value) {
  const ms = toMillis(value);
  if (!ms) return String(value || "");
  try { return new Intl.DateTimeFormat(undefined, {dateStyle: "medium"}).format(new Date(ms)); }
  catch { return String(value); }
}

// Where a source is published: its official locator when the pack has one.
function sourceLocator(src) {
  return src ? (src.official_reference || src.publication || src.oj_reference ||
                src.citation || src.section || src.title || "") : "";
}

const LIFECYCLE_ORDER = ["draft", "technically_validated", "regulatory_reviewed", "pilot", "published", "superseded"];

// The least advanced lifecycle among several: a framework is only as reviewed
// as its least reviewed criterion.
function leastLifecycle(states) {
  const known = states.filter(s => LIFECYCLE_ORDER.includes(s));
  if (!known.length) return states.find(Boolean) || "";
  return known.sort((a, b) => LIFECYCLE_ORDER.indexOf(a) - LIFECYCLE_ORDER.indexOf(b))[0];
}

// The words for a lifecycle state: the server's label for it where the pack
// sends one (criterion, template or pack `lifecycle_labels`), else ours.
function lifecycleText(stage, subject = null, pack = null) {
  if (subject?.lifecycle === stage && subject?.lifecycle_label) return subject.lifecycle_label;
  const served = (pack?.lifecycle_labels || state.pack?.pack?.lifecycle_labels || {})[stage];
  return served || (COMPLIANCE_COPY.labels.lifecycle[stage] || {}).text || humanize(stage);
}

function mappingStatus({subject = null, pack = null, sources = [], lifecycle = "", legalStatuses = [], hint = false} = {}) {
  const M = COMPLIANCE_COPY.mapping;
  const stage = lifecycle || subject?.lifecycle || pack?.lifecycle || "draft";
  const record = reviewRecordOf(subject) || (REVIEWED_STATES.has(stage) ? reviewRecordOf(pack) : null);
  const name = record && (record.reviewer || record.reviewer_name || record.name || record.firm);
  const date = record && (record.reviewed_on || record.date || record.reviewed_at || record.review_date);
  const reviewed = name ? fillCopy(date ? M.reviewedBy : M.reviewedByUndated, {name, date: reviewDay(date)}) : "";
  const parts = [];
  if (stage === "regulatory_reviewed") {
    parts.push(reviewed || `${lifecycleText(stage, subject, pack)}, ${M.reviewMissing}`);
  } else {
    parts.push(lifecycleText(stage, subject, pack));
    parts.push(reviewed || M.notReviewed);
  }
  if (record?.review_overdue) parts.push(M.overdue);
  const statuses = new Map();
  for (const src of sources || []) {
    if (src?.legal_status) statuses.set(src.legal_status, src.legal_status_label || "");
  }
  for (const status of legalStatuses || []) if (!statuses.has(status)) statuses.set(status, "");
  for (const [status, label] of statuses) {
    parts.push(label || (COMPLIANCE_COPY.labels.legalStatus[status] || {}).text || humanize(status));
  }
  const locator = sourceLocator((sources || [])[0]);
  if (locator) parts.push(fillCopy(M.source, {source: locator}));
  if (pack?.pack_version) parts.push(fillCopy(M.pack, {version: pack.pack_version}));
  return h("div", {class: "mapping-status", dataset: {lifecycle: stage}},
    h("p", {class: "mapping-line"}, icon("file"), h("span", {}, parts.join(" · "))),
    hint ? h("p", {class: "mapping-hint"}, mappingHint()) : "");
}

// The permanent hint (§4B.4), in the server's words when it sends them.
function mappingHint() {
  return state.pack?.pack?.mapping_hint || COMPLIANCE_COPY.mapping.hint;
}

function criteriaExplainer() {
  const C = COMPLIANCE_COPY.criteria;
  const step = (n, key) => h("li", {},
    h("span", {class: "crit-step-n", "aria-hidden": "true"}, n),
    h("span", {}, h("span", {class: "strong"}, termUse(key)), " ", COMPLIANCE_TERMS[key][1]));
  return h("div", {class: "crit-explain"},
    h("h3", {class: "about-subhead"}, "How a criterion is judged"),
    h("p", {class: "crit-explain-lede"},
      h("span", {class: "strong"}, termUse("criterion")), ": ", COMPLIANCE_TERMS.criterion[1], " ", C.explainLede),
    h("ol", {class: "crit-steps"}, C.steps.map(([key], index) => step(String(index + 1), key))),
    h("p", {class: "sub"}, C.explainFoot));
}

// What the criteria screen remembers across redraws: the note to show once in
// the criterion that was just saved.
let criterionFlash = null;

async function renderCriteria() {
  await loadCore();
  if (param("answers")) return renderQuestionnaire();
  const C = COMPLIANCE_COPY.criteria;
  const box = h("div", {class: "criteria-page"});
  const scope = scopedStore();
  const store = selectInput(storeOptions(), scope.id, {"aria-label": "Store"});
  const framework = selectInput([["", "All frameworks"]], param("framework"), {"aria-label": "Framework"});
  const status = selectInput([["", "Any status"],
    ...Object.entries(CRITERION_STATUS).map(([key, meta]) => [key, meta.text])],
    param("status"), {"aria-label": "Status"});
  const search = textInput(param("q"), {type: "search", placeholder: "Search title, citation or id",
                                        "aria-label": "Search criteria"});
  const count = h("span", {class: "result-count", role: "status"}, "");
  const summary = h("div", {class: "crit-summary"});
  const list = h("div", {class: "crit-rows"});
  const out = h("div", {});
  let result = null;

  let pack = null;
  try {
    pack = await loadPack();
    const frameworks = [...new Set(pack.criteria.map(c => c.framework))].sort();
    framework.replaceChildren(...[["", "All frameworks"], ...frameworks.map(f => [f, f])]
      .map(([value, label]) => h("option", {value, selected: value === param("framework")}, label)));
    framework.value = frameworks.includes(param("framework")) ? param("framework") : "";
  } catch (e) {
    box.append(pageHeader("criteria"));
    box.append(panel("Criteria", unavailableState(unavailableReason(e),
      "The criterion pack is served by the compliance API.")));
    return box;
  }

  const matches = c => {
    const q = search.value.trim().toLowerCase();
    if (framework.value && c.framework !== framework.value) return false;
    if (!q) return true;
    return [c.title, c.paraphrase, c.criterion_id, c.framework, ...(c.sources || []).map(s => s.citation || s.section)]
      .some(text => String(text || "").toLowerCase().includes(q));
  };

  // Filters narrow what is already on screen; only a store change re-reads.
  function drawList() {
    const assessments = new Map(((result || {}).assessments || []).map(a => [a.criterion_id, a]));
    // An evaluated criterion the loaded pack does not list is still shown.
    const known = new Set(pack.criteria.map(c => c.criterion_id));
    const all = [...pack.criteria, ...[...assessments.values()].filter(a => !known.has(a.criterion_id))
      .map(a => ({criterion_id: a.criterion_id, framework: a.framework}))];
    const inFramework = all.filter(c => !framework.value || c.framework === framework.value);
    const shown = all.filter(matches)
      .filter(c => !result || !status.value || assessments.get(c.criterion_id)?.status === status.value);
    count.textContent = `${number(shown.length)} of ${countText(all.length, COMPLIANCE_COPY.questionnaire.criteria)}`;
    if (result) summary.replaceChildren(criterionSummaryChips(inFramework, assessments, status.value, pick));
    const open = param("criterion");
    list.replaceChildren(...(shown.length
      ? shown.map(c => criterionCard(assessments.get(c.criterion_id) || null, {
          criterion: c, store: result ? store.value : "", redraw: draw,
          auditId: result?.audit_id, observed: result ? observedIn(result) : [], open: c.criterion_id === open}))
      : [emptyState("No criterion matches these filters.",
                    {action: clearFilters, actionLabel: "Clear filters"})]));
    if (open && shown.some(c => c.criterion_id === open)) {
      setTimeout(() => {
        const node = document.getElementById(criterionAnchor(open));
        node?.scrollIntoView?.({block: "start", behavior: "smooth"});
        node?.querySelector?.(".crit-flash")?.focus?.();
      }, 0);
    }
  }

  function pick(key) {
    status.value = status.value === key ? "" : key;
    setParams({status: status.value});
    drawList();
  }

  function clearFilters() {
    framework.value = ""; status.value = ""; search.value = "";
    setParams({framework: "", status: "", q: ""});
    drawList();
  }

  async function draw() {
    status.disabled = !store.value;
    if (!store.value) {
      result = null;
      summary.replaceChildren();
      out.replaceChildren(panel("Criteria", h("div", {},
        statusLine(C.noStore, "info"),
        list)));
      drawList();
      return;
    }
    out.replaceChildren(loadingState(C.loading));
    try {
      const body = {};
      if (param("audit")) body.audit_id = param("audit");
      result = await api(`/stores/${encodeURIComponent(store.value)}/criteria`,
                         {method: "POST", body: JSON.stringify(body)});
      const s = result.summary || {};
      out.replaceChildren(
        panel("Where these criteria stand", h("div", {class: "crit-standing"},
          summary,
          statusLine(s.note || "", "info"),
          // Why a stored decision was or was not applied, as the server says it.
          ...(((result.inputs || {}).notes) || []).map(note => statusLine(note, "medium")),
          h("div", {class: "bar crit-standing-bar"},
            h("p", {class: "sub"}, fillCopy(C.evaluatedAgainst, {audit: result.audit_id || "unknown"})),
            h("button", {class: "btn small", type: "button",
                         onclick: () => goTo("criteria", {answers: "1", store: store.value,
                                                          framework: framework.value})},
              icon("list"), C.answerAll)),
          h("details", {class: "crit-coverage"},
            h("summary", {}, icon("info"), "Assessment coverage behind these criteria"),
            coverageChart(result.coverage || {})))),
        panel("Criteria", list));
      drawList();
    } catch (e) {
      result = null;
      out.replaceChildren(panel("Criteria", e.status === 409
        ? unavailableState(C.noAudit, C.noAuditDetail)
        : errorState(unavailableReason(e), draw)));
    }
  }

  store.addEventListener("change", () => { setParams({store: store.value, criterion: ""}); draw(); });
  framework.addEventListener("change", () => { setParams({framework: framework.value}); drawList(); });
  status.addEventListener("change", () => { setParams({status: status.value}); drawList(); });
  search.addEventListener("input", () => { setParams({q: search.value.trim()}); drawList(); });

  // The store is the screen's scope, so it sits in the header; the filters
  // below only narrow what that store's evaluation shows.
  box.append(pageHeader("criteria", undefined, null, {scope: fieldTip("Store", store, C.storeTip)}));
  const frameworkCount = new Set(pack.criteria.map(c => c.framework)).size;
  box.append(pageIntro("criteria", {
    facts: [
      ["Criteria", number(pack.criteria.length)],
      ["Frameworks", number(frameworkCount)],
      ["Store", param("store") || "—", param("store") ? "latest saved assessment" : "not chosen"],
    ],
    steps: C.steps2,
    explain: criteriaExplainer(),
    actions: [
      introAction("What each framework requires", "layers",
                  () => goTo("frameworks", param("framework") ? {framework: param("framework")} : {})),
      introAction("Documents", "file", () => goTo("evidence")),
      can("operator") ? introAction("Run an assessment", "shield", () => goTo("assess", param("store") ? {store: param("store")} : {})) : null,
    ],
  }));
  box.append(h("div", {class: "crit-tools", role: "search", "aria-label": "Filter criteria"},
    field("Framework", framework), field("Status", status),
    h("label", {class: "field crit-search"}, h("span", {}, "Search"), search),
    count));
  box.append(h("div", {class: "crit-packline"},
    mappingStatus({pack: pack.pack, lifecycle: leastLifecycle(pack.criteria.map(c => c.lifecycle).concat(pack.pack?.lifecycle || [])),
                   hint: true}),
    rememberedStoreNote(scope)));
  box.append(out);
  await draw();
  return box;
}

// ----------------------------------------------------------- questionnaire ---
// One store's applicability questions, each asked once (§4B.3, C-3). A saved
// answer applies to every criterion that shares the question, because the
// server stores answers per store and question. Unanswered reads "Not sure
// yet", never "no". Route: #/criteria?answers=1&store=<id>[&framework=<f>].
async function renderQuestionnaire() {
  const Q = COMPLIANCE_COPY.questionnaire;
  const storeId = param("store");
  const box = h("div", {class: "criteria-page questionnaire"});
  const back = {label: Q.back, className: "remediation-back", onclick: () => climbOut("criteria")};
  const title = storeId ? fillCopy(Q.heading, {store: storeId}) : "Questions";
  let pack = null;
  try { pack = await loadPack(); }
  catch (e) {
    box.append(pageHeader(title, Q.lede, null, {literal: true, back}),
      panel("Questions", unavailableState(unavailableReason(e), "The criterion pack is served by the compliance API.")));
    return box;
  }
  const storeSel = selectInput(storeOptions(), storeId, {"aria-label": "Store"});
  storeSel.addEventListener("change", () => setParams({store: storeSel.value}));
  box.append(pageHeader(title, Q.lede, null, {literal: true, back,
    scope: fieldTip("Store", storeSel, COMPLIANCE_COPY.forms.answers.needStore)}));
  if (!storeId) {
    box.append(panel("Questions", statusLine(Q.noStore, "info")));
    return box;
  }

  // Questions and the criteria each one answers: from the server's view of
  // this store when it gives them, else from the pack.
  let stored = {answers: {}};
  let readError = "";
  try { stored = await api(`/stores/${encodeURIComponent(storeId)}/applicability`); }
  catch (e) { readError = unavailableReason(e); }
  const fromPack = new Map();
  for (const c of pack.criteria || []) {
    for (const q of c.applicability_questions || []) {
      fromPack.set(q, [...(fromPack.get(q) || []), c.criterion_id]);
    }
  }
  const served = Array.isArray(stored.questions) && stored.questions.length
    ? stored.questions.map(q => [q.question, q.criteria || fromPack.get(q.question) || []])
    : [...fromPack.entries()];
  const inFramework = id => !param("framework") ||
    (packCriterion(id)?.framework || frameworkOfCriterion(id)) === param("framework");
  const questions = served.map(([question, ids]) => [question, ids.filter(inFramework)])
    .filter(([, ids]) => ids.length);
  if (!questions.length) {
    box.append(panel("Questions", emptyState(Q.none)));
    return box;
  }
  const answerOf = question => ((stored.answers || {})[question] || {}).answer || "requires_confirmation";
  const editable = can("compliance");
  const status = h("p", {class: "inline-status questionnaire-status", role: "status", tabindex: "-1"});
  const criteriaCovered = new Set(questions.flatMap(([, ids]) => ids));
  const groups = questions.map(([question, ids]) => {
    const meta = (pack.applicability_questions || {})[question] || {};
    const row = (stored.answers || {})[question];
    const group = choiceGroup(questionText(question),
      Object.entries(Q.options).map(([key, label]) => [key, label, ""]), answerOf(question), {disabled: !editable});
    group.classList.add("questionnaire-q");
    group.dataset.question = question;
    group.append(
      h("span", {class: "sub choice-who"}, row
        ? fillCopy(COMPLIANCE_COPY.forms.answers.who, {
            answer: complianceLabel("applicabilityAnswer", row.answer).text,
            who: row.answered_by || "someone", when: relativeTime(row.answered_at)})
        : COMPLIANCE_COPY.forms.answers.nobody),
      h("details", {class: "questionnaire-why"},
        h("summary", {}, countText(ids.length, Q.affects)),
        meta.help ? h("p", {class: "sub"}, meta.help) : "",
        h("ul", {class: "questionnaire-criteria"}, ids.map(id => h("li", {},
          h("button", {class: "link", type: "button",
                       onclick: () => goTo("criteria", {store: storeId, criterion: id})},
            criterionTitle(packCriterion(id), id)),
          " ", h("span", {class: "sub mono"}, id))))));
    return {question, group, initial: answerOf(question)};
  });
  const progress = () => {
    const answered = groups.filter(g => (g.group.value || "requires_confirmation") !== "requires_confirmation").length;
    return fillCopy(Q.progress, {answered: number(answered), total: number(groups.length)});
  };
  const progressLine = h("span", {class: "sub questionnaire-progress"}, progress());
  for (const g of groups) for (const input of g.group.inputs) {
    input.addEventListener("change", () => { progressLine.textContent = progress(); });
  }
  const form = h("form", {class: "inline-form questionnaire-form", "aria-labelledby": "questionnaire-h",
    novalidate: "novalidate",
    onsubmit: async event => {
      event?.preventDefault?.();
      if (!editable) return;
      const answers = {};
      for (const g of groups) {
        const value = g.group.value || "requires_confirmation";
        if (value !== g.initial) answers[g.question] = value;
      }
      status.classList.remove("is-error");
      if (!Object.keys(answers).length) {
        status.textContent = Q.nothingChanged;
        status.focus?.();
        return;
      }
      try {
        await api(`/stores/${encodeURIComponent(storeId)}/applicability`,
                  {method: "POST", body: JSON.stringify({answers})});
        for (const g of groups) g.initial = g.group.value || "requires_confirmation";
        const when = new Intl.DateTimeFormat(undefined, {timeStyle: "short"}).format(new Date());
        status.textContent = `${Q.saved} ${fillCopy(Q.savedAt, {progress: progress(), when})}`;
        announce(Q.saved);
      } catch (e) {
        status.textContent = e.status === 403 ? refusalText(e) : unavailableReason(e);
        status.classList.add("is-error");
      }
      status.focus?.();
    }},
    h("h2", {class: "panel-heading", id: "questionnaire-h"},
      fillCopy(Q.scope, {questions: countText(groups.length, Q.questions),
                         criteria: countText(criteriaCovered.size, Q.criteria)})),
    readError ? statusLine(`${Q.readFailed} ${readError}`, "medium") : "",
    editable ? "" : statusLine(Q.readOnly, "info"),
    groups.map(g => g.group),
    h("div", {class: "bar inline-actions"},
      editable ? h("button", {class: "btn primary", type: "submit"}, Q.save) : "",
      progressLine),
    status);
  box.append(panel(null, form));
  return box;
}

function observedIn(result) {
  // Every observation this evaluation read, so a criterion can show a sibling
  // observation beside its own (PCI storage encryption) without inheriting it.
  return [...(result.assessments || []).flatMap(a => a.observations || []),
          ...(result.crypto_context || [])];
}

// Counts by status for the framework in view. Each one filters the list; none
// adds up to a score, and a zero is shown rather than hidden.
function criterionSummaryChips(criteria, assessments, active, pick) {
  const counts = {};
  for (const c of criteria) {
    const s = assessments.get(c.criterion_id)?.status;
    if (s) counts[s] = (counts[s] || 0) + 1;
  }
  return h("div", {class: "crit-chips", role: "group", "aria-label": "Filter by status"},
    Object.entries(CRITERION_STATUS).map(([key, meta]) => h("button", {
      class: `crit-chip${active === key ? " is-on" : ""}`, type: "button",
      "aria-pressed": String(active === key), title: CRITERION_STATUS_HELP[key],
      dataset: {status: key}, onclick: () => pick(key)},
      h("span", {class: `crit-chip-dot sev-${meta.tone}`, "aria-hidden": "true"}),
      h("span", {class: "crit-chip-n"}, number(counts[key] || 0)),
      h("span", {class: "crit-chip-k"}, meta.text))));
}

function criterionAnchor(id) {
  return `crit-${String(id).replace(/[^A-Za-z0-9_-]/g, "-")}`;
}

// What to do next, in one line, from the evaluation's own fields.
function criterionNextStep(a) {
  const N = COMPLIANCE_COPY.criteria.nextStep;
  if (!a) return N.noStore;
  const pending = Object.values(a.applicability || {}).filter(v => v === "requires_confirmation").length;
  const exceptions = a.exceptions || [];
  const active = exceptions.find(e => e.status === "active");
  const labels = list => {
    const names = list.map(evidenceName);
    return names.length > 2 ? fillCopy(N.more, {names: names.slice(0, 2).join(", "), n: number(names.length - 2)})
                            : names.join(", ");
  };
  const who = a.reviewer?.reviewer || N.someone;
  switch (a.status) {
    case "not_assessed":
      return a.applicability_status === "excluded" ? N.excluded : countText(pending, N.answer);
    case "evidence_needed": {
      const rejected = (a.missing_evidence || []).filter(name => requirementState(a, name) === "rejected");
      return rejected.length ? fillCopy(N.replaceRejected, {names: labels(rejected)})
                             : fillCopy(N.supply, {names: labels(a.missing_evidence || [])});
    }
    case "under_review": return N.underReview;
    case "gap_identified":
      if (active) return fillCopy(N.exceptionActive, {when: relativeDay(active.expires_at)});
      return a.technical_result === "failed" ? N.failed : N.reviewerGap;
    case "satisfied_for_scope": return fillCopy(N.satisfied, {who});
    case "not_applicable": return fillCopy(N.notApplicable, {who});
    default: return "";
  }
}

// One requirement's state, read from the evaluation: missing and rejected
// both leave it in missing_evidence, and the reviews say which.
function requirementState(a, name) {
  const reviews = (a.evidence_reviews || []).filter(r => r.requirement === name);
  if ((a.missing_evidence || []).includes(name)) {
    return reviews.some(r => r.state === "rejected") && !reviews.some(r => r.accepted) ? "rejected" : "missing";
  }
  return reviews.some(r => r.accepted) ? "accepted" : "submitted";
}

// One criterion: a scannable row that opens in place. Its id is small; its
// title and what it asks lead. The detail is in the document from the start,
// so every action is reachable and the row can be deep-linked (?criterion=).
function criterionCard(a, {criterion = null, store = "", redraw = () => {}, auditId, observed = [], open = false} = {}) {
  const c = criterion || packCriterion(a?.criterion_id) || {criterion_id: a?.criterion_id, framework: a?.framework};
  const id = c.criterion_id;
  const anchor = criterionAnchor(id);
  const detail = h("div", {class: "crit-detail", id: `${anchor}-detail`, hidden: !open},
    criterionDetail(c, a, {store, redraw, auditId, observed}));
  const head = h("button", {class: "crit-row-head", type: "button", "aria-expanded": String(open),
                            "aria-controls": `${anchor}-detail`, onclick: toggle},
    h("span", {class: "crit-row-status"}, a
      ? complianceChip("criterionStatus", a.status)
      : stateChip("unknown", "not evaluated")),
    h("span", {class: "crit-row-main"},
      h("span", {class: "crit-row-title"}, criterionTitle(c)),
      c.paraphrase ? h("span", {class: "crit-row-asks"}, c.paraphrase) : "",
      h("span", {class: "crit-row-id mono"}, id)),
    h("span", {class: "crit-row-cite"},
      h("span", {class: "strong"}, c.framework || ""),
      citationOf(c) ? h("span", {class: "sub"}, citationOf(c)) : ""),
    h("span", {class: "crit-row-next"}, criterionNextStep(a)),
    h("span", {class: "crit-row-chev", "aria-hidden": "true"}));
  const card = h("article", {class: `criterion crit-row${a ? ` criterion-${a.status}` : ""}${open ? " is-open" : ""}`,
                             id: anchor, dataset: {criterion: id, status: a?.status || ""}},
    h("h3", {class: "crit-row-h"}, head), detail);

  function toggle() {
    const opening = head.getAttribute("aria-expanded") !== "true";
    // One open at a time, so the address names the one on screen.
    for (const other of card.parentNode?.children || []) {
      if (other === card || !other.classList?.contains("crit-row")) continue;
      other.classList.remove("is-open");
      other.querySelector?.(".crit-row-head")?.setAttribute("aria-expanded", "false");
      const d = other.querySelector?.(".crit-detail");
      if (d) d.hidden = true;
    }
    head.setAttribute("aria-expanded", String(opening));
    detail.hidden = !opening;
    card.classList.toggle("is-open", opening);
    setParams({criterion: opening ? id : ""});
  }
  return card;
}

function criterionDetail(c, a, {store, redraw, auditId, observed}) {
  const C = COMPLIANCE_COPY.criteria;
  const notes = state.pack?.specification_notes || {};
  const terms = Object.entries(state.pack?.terms || {})
    .filter(([term]) => new RegExp(`\\b${term}\\b`).test(c.paraphrase || ""));
  const limits = a ? (a.limitations || []) : (c.limitations || []);
  const flash = a && criterionFlash?.id === c.criterion_id ? criterionFlash.text : "";
  if (flash) criterionFlash = null;
  const flashNode = flash ? statusLine(flash, "ok", {live: true}) : "";
  if (flashNode) { flashNode.classList.add("crit-flash"); flashNode.setAttribute("tabindex", "-1"); }

  return [
    flashNode,
    plainLegal({plain: c.plain, title: criterionTitle(c), legal: c.paraphrase}, {
      tags: [...(c.sources || []).map(src => sourceTag(src)),
             c.specification ? h("span", {class: "tag", title: notes[c.specification] || ""},
                                 complianceLabel("specification", c.specification).text) : ""].filter(Boolean),
      extra: [
        c.specification && notes[c.specification] ? h("p", {class: "sub"}, notes[c.specification]) : "",
        terms.length ? h("dl", {class: "crit-terms"}, terms.flatMap(([term, meaning]) =>
          [h("dt", {}, term), h("dd", {}, meaning)])) : ""],
      mapping: mappingStatus({subject: c, pack: state.pack?.pack, sources: c.sources}),
    }),

    a ? criterionStanding(a) : "",

    h("div", {class: "crit-section-k"}, C.judgedHeading),
    a
      ? h("div", {class: "criterion-fields"},
          applicabilityField(a),
          criterionField(C.fields.check,
            complianceChip("technicalResult", a.technical_result),
            criterionTechnicalNote(a),
            checksLine(c),
            ...(a.observations || []).filter(o => isolationReach(o)).slice(0, 3).map(o =>
              h("div", {class: "sub"}, `Isolation${o.collection ? ` (${o.collection})` : ""}: `, isolationReach(o)))),
          criterionField(C.fields.evidence,
            complianceChip("evidenceStatus", a.evidence_sufficiency),
            (a.missing_evidence || []).length ? countText(a.missing_evidence.length, C.notAccepted) : C.nothingOutstanding,
            h("span", {class: "sub"}, complianceLabel("evidenceStatus", a.evidence_sufficiency).help || "")),
          reviewerField(a))
      : criterionSpecJudging(c),
    a ? reviewerDecisionNote(a) : "",
    a ? cryptoObservations(a, {store, observed}) : "",
    a ? determinationLines(a) : "",
    a && (a.fallback_required || []).length
      ? h("p", {class: "crypto-fallback"}, icon("file"),
          fillCopy(C.fallbackRequired, {names: a.fallback_required.map(evidenceName).join(", ")}))
      : "",

    h("div", {class: "crit-section-k"}, C.documentsHeading),
    requirementList(c, a),

    a ? h("details", {class: "evidence-data"},
          h("summary", {}, icon("eye"), fillCopy(C.observedSummary, {n: number((a.observations || []).length)})),
          observationsTable(a)) : "",
    limits.length || c.interpretation_notes
      ? h("details", {class: "evidence-data"},
          h("summary", {}, icon("info"), C.limitsSummary),
          limits.length ? h("ul", {class: "limitations"}, limits.map(l => h("li", {}, l))) : "",
          c.interpretation_notes ? h("p", {class: "crit-note"}, c.interpretation_notes) : "")
      : "",

    a ? criterionActions(a, {store, auditId, redraw})
      : statusLine(C.chooseStore, "info"),
  ];
}

// The criterion's actions, and one slot under them where a form opens in
// place (C-4). One form at a time; the button that opened it says so through
// aria-expanded, and Cancel hands focus back to it. After a save the list
// redraws against the server and the criterion reopens with a saved note.
function criterionActions(a, {store, auditId, redraw}) {
  const F = COMPLIANCE_COPY.forms;
  const anchor = criterionAnchor(a.criterion_id);
  const slot = h("div", {class: "crit-inline", id: `${anchor}-form`});
  const pending = Object.values(a.applicability || {}).filter(v => v === "requires_confirmation").length;
  const needs = (a.missing_evidence || []).length;
  let openKey = "";
  let opener = null;
  const buttons = [];
  const close = ({focus = true} = {}) => {
    slot.replaceChildren();
    for (const b of buttons) b.setAttribute("aria-expanded", "false");
    if (focus) opener?.focus?.();
    openKey = "";
  };
  const done = message => {
    criterionFlash = {id: a.criterion_id, text: message};
    announce(message);
    setParams({criterion: a.criterion_id});
    redraw();
  };
  const opens = (key, label, glyph, build, primary = false) => {
    const button = h("button", {class: `btn small${primary ? " primary" : ""}`, type: "button",
                                "aria-expanded": "false", "aria-controls": slot.id, dataset: {form: key},
                                onclick: () => {
      if (openKey === key) { close(); return; }
      close({focus: false});
      openKey = key;
      opener = button;
      button.setAttribute("aria-expanded", "true");
      const form = build({close, done});
      slot.replaceChildren(form);
      focusFirstField(form);
    }}, icon(glyph), label);
    buttons.push(button);
    return button;
  };
  const writer = store && can("compliance");
  return h("div", {class: "crit-action-area"},
    h("div", {class: "bar crit-actions"},
      writer ? opens("decision", a.stored_decision ? F.decision.openAgain : F.decision.open, "check",
                     ctx => decisionForm(a, {auditId, store, ...ctx}), true) : "",
      writer && pending ? opens("answers", countText(pending, F.answers.open), "edit",
                                ctx => answersForm(a, {store, ...ctx})) : "",
      writer && needs ? opens("attach", countText(needs, F.attach.open), "file",
                              ctx => attachForm(a, {store, ...ctx})) : "",
      can("compliance")
        ? h("button", {class: "btn small", type: "button",
                       onclick: () => requestExceptionModal({criterion: a.criterion_id, scope: store})},
            icon("key"), "Request exception")
        : "",
      h("button", {class: "btn small", type: "button",
                   onclick: () => exportCriterionPosition(a, {store, auditId})},
        icon("file"), "Export position")),
    slot);
}

// The status, why, and what is attached to it: gaps and exceptions. An
// exception is shown beside the gap and never in place of it.
function criterionStanding(a) {
  const C = COMPLIANCE_COPY.criteria;
  const exceptions = a.exceptions || [];
  return h("div", {class: "crit-standing-box"},
    h("div", {class: "crit-standing-line"},
      complianceChip("criterionStatus", a.status),
      h("span", {class: "crit-why"}, a.rationale || CRITERION_STATUS_HELP[a.status] || "")),
    (a.gaps || []).length ? h("ul", {class: "limitations"}, a.gaps.map(g => h("li", {}, namedArtifacts(g)))) : "",
    exceptions.length
      ? h("ul", {class: "crit-exceptions"}, exceptions.map(e => h("li", {},
          exceptionChip(e.status, {long: true}),
          h("span", {class: "sub"}, fillCopy(C.exceptionLine[e.status] || "", {when: relativeDay(e.expires_at)})),
          e.rationale ? h("span", {class: "sub"}, fillCopy(C.exceptionReason, {text: e.rationale})) : "")))
      : "");
}

// Server sentences name artifacts by key; show the vocabulary's names instead,
// and make any other key readable.
function namedArtifacts(text) {
  const types = state.pack?.evidence_types || {};
  return String(text || "").replace(/\b[a-z]+(?:_[a-z0-9]+)+\b/g, key => types[key] ? types[key].label : humanize(key).toLowerCase());
}

function applicabilityField(a) {
  const C = COMPLIANCE_COPY.criteria;
  const meta = complianceLabel("applicabilityStatus", a.applicability_status);
  const answers = Object.entries(a.applicability || {});
  const pending = answers.filter(([, v]) => v === "requires_confirmation").length;
  return criterionField(C.fields.applies, complianceChip("applicabilityStatus", a.applicability_status),
    pending ? countText(pending, C.unanswered) : answers.length ? C.settled : C.alwaysApplies,
    h("span", {class: "sub"}, meta.help || ""),
    answers.length ? h("ul", {class: "crit-answers"}, answers.map(([q, v]) => h("li", {},
      h("span", {}, questionText(q)),
      h("span", {class: `crit-answer crit-answer-${v === "requires_confirmation" ? "unsure" : v}`},
        complianceLabel("applicabilityAnswer", v).text)))) : "");
}

function checksLine(c) {
  const checks = c.technical_checks || [];
  return checks.length ? h("span", {class: "sub"}, `Checks: ${checks.map(checkLabel).join(", ")}.`) : "";
}

// Before a store is chosen: what would be judged, without any state.
function criterionSpecJudging(c) {
  const C = COMPLIANCE_COPY.criteria;
  const questions = c.applicability_questions || [];
  return h("div", {class: "crit-cols"},
    critColumn(C.specNotAsked, "user", questions.length
      ? questions.map(q => critItem(questionText(q), ""))
      : [h("li", {class: "sub"}, C.specNoQuestions)]),
    critColumn(C.specObserved, "shield", (c.technical_checks || []).length
      ? c.technical_checks.map(name => critItem(checkLabel(name), (CHECK_GLOSSARY[name] || [])[1] || ""))
      : [h("li", {class: "sub"}, C.specNothing)]),
    critColumn(C.specDecided, "check", [critItem(C.specDecidedBy, C.specDecidedHow)]));
}

// Each document the criterion needs: what it is, concrete examples, and —
// once a store is evaluated — its state and the reviews behind that state.
function requirementList(c, a) {
  const C = COMPLIANCE_COPY.criteria;
  const required = c.manual_evidence || [];
  const conditional = a ? (a.fallback_required || []) : (c.fallback_evidence || []);
  const names = [...required, ...conditional.filter(n => !required.includes(n))];
  const reviews = a ? (a.evidence_reviews || []) : [];
  const stray = reviews.filter(r => r.requirement && !names.includes(r.requirement));
  if (!names.length && !stray.length) {
    return h("p", {class: "sub"}, a && a.technical_result !== "passed" && (c.fallback_evidence || []).length
      ? C.nothingYet : C.nothingRequired);
  }
  return h("ul", {class: "crit-reqs"},
    names.map(name => {
      const info = evidenceInfo(name);
      const st = a ? requirementState(a, name) : "";
      const mine = reviews.filter(r => r.requirement === name);
      return h("li", {class: "crit-req", dataset: {requirement: name}},
        h("div", {class: "crit-req-head"},
          h("span", {class: "strong"}, info.label),
          conditional.includes(name) && !required.includes(name)
            ? h("span", {class: "tag evidence-conditional"}, C.conditional) : "",
          st ? complianceChip("requirementState", st) : ""),
        info.what ? h("p", {class: "sub"}, info.what) : "",
        (info.examples || []).length
          ? h("p", {class: "crit-req-ex"}, h("span", {class: "crit-req-exk"}, "For example: "),
              info.examples.join("; "), ".")
          : "",
        st === "missing" && mine.some(r => r.accepted) ? h("p", {class: "sub"}, C.staleAcceptance) : "",
        mine.map(r => reviewLine(r)));
    }),
    stray.map(r => h("li", {class: "crit-req crit-req-stray"},
      h("div", {class: "crit-req-head"},
        h("span", {class: "strong"}, evidenceName(r.requirement)),
        stateChip("unknown", C.strayChip)),
      h("p", {class: "sub"}, C.stray),
      reviewLine(r))));
}

function reviewLine(r) {
  const who = r.reviewer ? ` by ${r.reviewer}` : "";
  const verdict = `${complianceLabel("reviewState", r.state).text}${who}`;
  return h("p", {class: "crit-review-line"},
    icon("file"),
    h("span", {}, h("span", {class: "strong"}, verdict), ": ",
      h("span", {class: "mono"}, r.artifact_id || "document"),
      r.period ? ` for ${r.period}` : "",
      r.reason ? ` — ${r.reason}` : r.accepted || r.state === "rejected" ? " — no reason recorded" : ""));
}

// The reviewer, as recorded: who decided what, when, and whether that stored
// decision applies to the assessment on screen. A decision made against a
// later assessment, or against another wording of the criterion, is shown and
// explained, never silently applied or silently dropped.
function reviewerField(a) {
  const C = COMPLIANCE_COPY.criteria;
  const applied = a.reviewer;
  const stored = a.stored_decision;
  if (applied) {
    const when = applied.decided_at ? ` · ${relativeTime(applied.decided_at)}` : "";
    return criterionField(C.fields.reviewer,
      applied.conclusion ? complianceChip("conclusion", applied.conclusion) : stateChip("info", "Decided"),
      `${applied.reviewer}${when}${a.decision_source === "what_if" ? ` · ${C.previewOnly}` : ""}`);
  }
  if (stored && stored.applied === false) {
    return criterionField(C.fields.reviewer, stateChip("medium", C.notAppliedChip),
                          fillCopy(C.notAppliedNote, {who: stored.reviewer}));
  }
  return criterionField(C.fields.reviewer, stateChip("unknown", "None"), C.noDecision);
}

function reviewerDecisionNote(a) {
  const C = COMPLIANCE_COPY.criteria;
  const stored = a.stored_decision;
  if (!stored) return "";
  const conclusion = complianceLabel("conclusion", stored.conclusion).text;
  let who = stored.decided_at
    ? fillCopy(C.recordedWhen, {who: stored.reviewer, conclusion, when: relativeTime(stored.decided_at)})
    : fillCopy(C.recorded, {who: stored.reviewer, conclusion});
  if (stored.audit_id) who += ` for assessment ${stored.audit_id}`;
  if (stored.applied === false) {
    const why = stored.not_applied_note ||
      (COMPLIANCE_COPY.labels.notApplied[stored.not_applied_reason] || {}).text ||
      `${humanize(stored.not_applied_reason)}.`;
    return statusLine(`${who}. ${fillCopy(C.notAppliedLine, {why})}`, "medium");
  }
  const parts = [who + "."];
  if (stored.rationale) parts.push(fillCopy(C.why, {text: stored.rationale}));
  if (stored.carried_forward) parts.push(C.carried);
  if (a.what_if_ignored) parts.push(C.previewIgnored);
  return statusLine(parts.join(" "), "info");
}

// A criterion's position, exportable as it stands: what applies, what was
// observed, what evidences it, what is tolerated, and who decided. The export
// carries its own caveats so it cannot be read as more settled than it is.
function exportCriterionPosition(a, {store, auditId}) {
  const position = {
    exported_at: new Date().toISOString(),
    store, audit_id: auditId || null,
    criterion_id: a.criterion_id, framework: a.framework,
    pack_version: a.pack_version,
    status: a.status, status_label: complianceLabel("criterionStatus", a.status).text,
    rationale: a.rationale,
    applicability: {status: a.applicability_status, answers: a.applicability},
    technical: {result: a.technical_result, coverage: a.technical_coverage,
                observations: a.observations || []},
    evidence: {sufficiency: a.evidence_sufficiency,
               missing: a.missing_evidence || [],
               reviews: a.evidence_reviews || []},
    exceptions: a.exceptions || [],
    reviewer: a.reviewer || null,
    gaps: a.gaps || [],
    limitations: a.limitations || [],
    caveats: [...COMPLIANCE_COPY.exportCaveats],
  };
  const name = `vecshield-position-${String(a.criterion_id).replace(/[^a-zA-Z0-9_-]/g, "_")}.json`;
  downloadText(JSON.stringify(position, null, 2), name, "application/json",
               `Position — ${a.criterion_id}`);
  return position;
}

// Crypto observations keep their evidence state on the card, so "the store
// does not expose this" reads differently from "this was observed and failed".
const PCI_STORAGE_CRITERION = "PCI-DSS-3-STORAGE-01";
const CRYPTO_OBSERVATION_CAP = 8;

function cryptoObservationItem(label, o) {
  return h("li", {class: "crypto-obs-item", dataset: {check: o.check || ""}},
    h("span", {class: "strong"}, label),
    h("span", {class: "sub mono"}, o.collection || "store scope"),
    recordChip(o),
    o.reason ? h("span", {class: "sub"}, o.reason) : "",
    cryptoNote(o),
    cryptoSupportBlock(o));
}

// Two reductions are not coverage gaps in the usual sense, and read wrongly as
// "coverage not applicable": the store cannot show the property, or the
// property does not come up for it at all (a filesystem store has no transport).
const TECHNICAL_COVERAGE_TEXT = {
  not_observable: "not observable through this store",
  does_not_arise: COMPLIANCE_COPY.technicalNote.does_not_arise,
  not_applicable: COMPLIANCE_COPY.technicalNote.not_applicable,
};

// The note under a criterion's check result. Where the property could not be
// established, it names why: the database does not support reporting it, or
// this store could not show it.
function criterionTechnicalNote(a) {
  const checks = a.technical_checks || (a.observations || []).map(o => o.check);
  const db = unsupportedDatabase(checks, a.observations);
  if (a.technical_coverage === "not_observable") {
    return db ? `not supported by ${db}` : technicalCoverageText("not_observable");
  }
  if (a.technical_result === "not_run" && !TECHNICAL_COVERAGE_TEXT[a.technical_coverage] &&
      unobservedOnly(checks, a.observations)) {
    return db ? `not supported by ${db}` : "not observable through this store";
  }
  return technicalCoverageText(a.technical_coverage);
}

function technicalCoverageText(coverage) {
  return TECHNICAL_COVERAGE_TEXT[coverage] || `coverage ${humanize(coverage || "unknown").toLowerCase()}`;
}

function uniqueObservations(list) {
  const seen = new Set();
  return list.filter(o => {
    const key = `${o.check}|${o.collection || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function cryptoObservations(a, {store, observed = []} = {}) {
  if (a.criterion_id === PCI_STORAGE_CRITERION) return pciStorageRows(a, {store, observed});
  const crypto = (a.observations || []).filter(o => (o.coverage || {}).crypto_state);
  if (!crypto.length) return "";
  const shown = crypto.slice(0, CRYPTO_OBSERVATION_CAP);
  return h("div", {class: "crypto-obs"},
    h("div", {class: "metric-k"}, "Cryptographic observations"),
    h("ul", {class: "crypto-obs-list"},
      shown.map(o => cryptoObservationItem(checkLabel(o.check), o)),
      crypto.length > shown.length
        ? h("li", {class: "sub"}, `and ${number(crypto.length - shown.length)} more in Observations`)
        : ""),
    store ? h("button", {class: "link", type: "button", onclick: () => goTo("crypto", {store})},
                icon("lock"), "Open the Crypto view for this store") : "");
}

// Requirement 3 asks for PAN to be unreadable wherever it is stored. Storage
// encryption and the representation of the PAN itself are two protections;
// they are shown as two rows, and the first never stands in for the second.
function pciStorageRows(a, {store, observed = []}) {
  const storage = uniqueObservations(observed.filter(o => o.check === "at_rest_encryption"));
  const pan = (a.observations || []).filter(o => o.check === "pan_representation");
  const row = (label, outcomes, missing) => outcomes.length
    ? outcomes.map(o => cryptoObservationItem(label, o))
    : [h("li", {class: "crypto-obs-item", dataset: {check: "none"}},
        h("span", {class: "strong"}, label), cryptoBadge("not_run"),
        h("span", {class: "sub"}, missing))];
  return h("div", {class: "crypto-obs crypto-obs-pci"},
    h("div", {class: "metric-k"}, "Two protections, shown apart"),
    h("ul", {class: "crypto-obs-list"},
      row("Storage encryption", storage,
          "No storage-encryption observation in this evaluation; see the Crypto view."),
      row("PAN data-level protection", pan,
          "This run recorded no PAN representation check.")),
    h("p", {class: "sub"},
      "Storage encryption is shown beside this criterion and never satisfies it: under " +
      "Requirement 3.5.1.2, disk- or partition-level encryption alone does not render PAN unreadable."),
    store ? h("button", {class: "link", type: "button", onclick: () => goTo("crypto", {store})},
                icon("lock"), "Open the Crypto view for this store") : "");
}

// An addressable (HIPAA) or risk-based (GDPR, SOC 2) measure may be absent
// with a documented determination. The determination only matters when the
// control was not observed; beside a passed control it is not needed.
const DETERMINATIONS = [
  ["addressable_determination", "Addressable determination",
   "Absent the safeguard, a documented determination and an equivalent alternative, where reasonable, are required."],
  ["risk_determination", "Risk determination",
   "Absent the measure, a documented risk assessment must explain why it is not appropriate here."],
];

function determinationLines(a) {
  const present = DETERMINATIONS.filter(([key]) => a[key] != null);
  if (!present.length) return "";
  // Only an observed absence makes the determination the deciding artifact.
  // Where the store could not show the control, the fallback statement comes
  // first; a "missing" determination there would read as a second demand.
  const absent = a.technical_result === "failed";
  const passed = a.technical_result === "passed";
  return h("div", {class: "determination"}, present.map(([key, label, why]) =>
    h("div", {class: "determination-row"},
      h("span", {class: "metric-k"}, label),
      absent ? complianceChip("determination", a[key])
        : stateChip("info", passed ? "Not needed" : "Only if absent"),
      h("span", {class: "sub"}, absent ? why
        : passed ? "The control was observed, so no determination is needed."
        : "Needed only if the control turns out to be absent; until then the fallback evidence carries the criterion."))));
}

// One of the four inputs. The value is a state chip or the state's own words;
// anything after the note explains it.
function criterionField(label, value, note, ...more) {
  return h("div", {class: "criterion-field"},
    h("div", {class: "metric-k"}, label),
    h("div", {class: "criterion-value"}, value instanceof Node ? value
      : String(value || "unknown").replace(/_/g, " ")),
    h("div", {class: "metric-s"}, note || ""),
    ...more);
}

// How far the isolation check reached: exhaustive within its query budget,
// sampled beyond it, or not applicable to a single-tenant collection.
function isolationReach(o) {
  const cov = o.coverage || {};
  if (o.check !== "tenant_isolation" || !(cov.method || cov.applicability)) return "";
  const chip = cov.applicability === "not_applicable" ? stateChip("info", "Single-tenant, not applicable")
    : cov.method === "exhaustive" ? stateChip("ok", "exhaustive")
    : stateChip("medium", `${cov.method || "sampled"}, partial`);
  const counts = [cov.cross_tenant_queries != null ? `${number(cov.cross_tenant_queries)} cross-tenant queries` : "",
                  cov.bleeds != null ? `${number(cov.bleeds)} ${cov.bleeds === 1 ? "bleed" : "bleeds"}` : ""]
    .filter(Boolean).join(" · ");
  return h("span", {class: "iso-reach"}, chip, counts ? h("span", {class: "sub"}, ` ${counts}`) : "");
}

// What the saved audit recorded for this criterion's checks, one row each.
function observationsTable(a) {
  const rows = (a.observations || []).map(o => h("tr", {},
    h("td", {}, h("div", {}, checkLabel(o.check || "-")), h("div", {class: "sub mono"}, o.check || "-")),
    h("td", {}, o.collection && param("store")
      ? h("button", {class: "link mono", type: "button",
                     onclick: () => goTo("schema", {store: param("store"), collection: o.collection})},
          o.collection)
      : o.collection || "(store)"),
    h("td", {}, o.outcome ? complianceLabel("outcome", o.outcome).text : "-"),
    h("td", {}, (o.coverage || {}).crypto_state
      ? recordChip(o) : h("span", {class: "sub"}, "—")),
    h("td", {}, h("div", {}, complianceLabel("technicalCoverage", (o.coverage || {}).status || "unknown").text), isolationReach(o)),
    h("td", {}, o.reason || "")));
  return rows.length
    ? table(["Check", "Collection", "Outcome", "Crypto state", "Coverage", "Reason"], rows)
    : unknownState("This assessment recorded nothing for this criterion's checks.",
                   "So its check result is “Not run”.");
}

function observationsModal(a) {
  modal(`Observations — ${criterionTitle(packCriterion(a.criterion_id), a.criterion_id)}`,
        observationsTable(a), null, "Close", {meta: a.criterion_id});
}


// The Findings area. Filtering, sorting, and paging all happen in the database,
// so the count on screen is the count of everything matching — not "of the
// first 500 we happened to fetch", which is how the old client-side filter
// quietly understated a backlog. For the same reason there is no filter here
// for what the API cannot filter on (detector confidence, counter-signals,
// framework, run): narrowing one page of rows in the browser would print a
// count that is not the count. Those are shown per row instead.

const CASE_STATE_TONE = {
  new: "unknown", triaged: "low", assigned: "low", in_progress: "low",
  awaiting_verification: "medium", verified: "ok", closed: "ok",
  false_positive: "info", duplicate: "info", risk_accepted: "medium",
  reopened: "critical",
};

// The working path a case walks, in order, and the other ways it can end.
// The second group are claims about the world, not progress: each needs a
// reason from a named person (vecshield_platform/cases.py), and none of them
// is a fix.
const CASE_LIFECYCLE = ["new", "triaged", "assigned", "in_progress",
                        "awaiting_verification", "verified", "closed"];
const CASE_OTHER = ["false_positive", "duplicate", "risk_accepted", "reopened"];
const CASE_CLAIM_NOTE = {
  false_positive: "a claim, not a fix", duplicate: "a claim, not a fix",
  risk_accepted: "accepted, not fixed",
};
// What the server asks of a move, mirrored so the form asks before it refuses.
// The server still decides; this only marks the fields.
const CASE_NEEDS_REASON = new Set(["false_positive", "duplicate", "risk_accepted", "closed"]);

// Columns the server can sort by (history.py FINDING_SORTS). Severity first is
// the triage order; the case column sorts by when the case last changed.
const FINDING_SORT_KEYS = ["severity", "created_at", "store", "case_updated_at"];

function caseLabel(name) {
  return String(name || "new").replace(/_/g, " ");
}

function caseBadge(state) {
  const name = String(state || "new");
  return stateChip(CASE_STATE_TONE[name] || "unknown", name);
}

// What a reader needs to know before moving a case to `to`.
function caseMoveHint(to) {
  if (!to) return "";
  if (to === "risk_accepted") {
    return "A claim, recorded with your name: a reason is required. The finding stays " +
           "visible and counted; accepting a risk does not fix it.";
  }
  if (CASE_NEEDS_REASON.has(to) && to !== "closed") {
    return "A claim about the world, recorded with your name: a reason is required. It is not a fix.";
  }
  return {
    closed: "Closing needs a reason.",
    verified: "Name the run that confirmed it, or say in the reason how you verified it.",
    assigned: "Assigning needs an owner.",
    awaiting_verification: "The fix is done; a later run, or a written statement, confirms it.",
    reopened: "Work resumes. The earlier decision stays in the history.",
  }[to] || "";
}

// A finding's matches by confidence class, and how many carry counter-signals.
const CONFIDENCE_ORDER = ["likely", "possible", "uncertain"];
const CONFIDENCE_TONE = {likely: "ok", possible: "medium", uncertain: "unknown"};

function findingConfidence(finding) {
  const evidence = finding.evidence || {};
  const explanations = evidence.explanations || [];
  const classes = {};
  let disputed = 0;
  for (const e of explanations) {
    const name = e.confidence || "uncertain";
    classes[name] = (classes[name] || 0) + 1;
    if ((e.counter_signals || []).length || e.disputed) disputed += 1;
  }
  const names = [...CONFIDENCE_ORDER.filter(k => classes[k]),
                 ...Object.keys(classes).filter(k => !CONFIDENCE_ORDER.includes(k))];
  return {total: explanations.length, classes, names, disputed,
          fromDetector: explanations.length > 0 || Boolean(evidence.detector_counts)};
}

// How sure the detectors were, and whether anything argues against them. A
// finding that is not a content-detector match (a CVE, a probe, posture) has
// no confidence class, which is said rather than left blank.
function confidenceCell(finding) {
  const c = findingConfidence(finding);
  if (!c.total) {
    return c.fromDetector
      ? stateChip("unknown", "not recorded",
          {title: "The detector recorded no confidence for these matches."})
      : h("span", {class: "sub", title: "Not a content-detector match, so no confidence class applies."},
          "n/a");
  }
  const breakdown = c.names.map(k => `${number(c.classes[k])} ${k}`).join(", ");
  const label = c.names.length === 1 ? c.names[0] : `${c.names[0]}–${c.names[c.names.length - 1]}`;
  // Mixed classes take the weakest one's tone: the chip must not read surer
  // than the least certain match behind it.
  const weakest = c.names[c.names.length - 1];
  return h("div", {class: "conf-cell"},
    stateChip(CONFIDENCE_TONE[weakest] || "unknown", label,
              {title: `${plural(c.total, "match", "matches")}: ${breakdown}`}),
    c.disputed
      ? stateChip("medium", `${number(c.disputed)} disputed`,
          {title: `${plural(c.disputed, "match", "matches")} with counter-signals: reasons the match may be wrong`})
      : "");
}

// Coverage of each store's latest audit, read once per visit to Findings. The
// detail panel reads it too, so it is kept here rather than refetched.
let findingsCoverage = null;
let findingsCoverageReady = null;

function coverageNote(coverage, scope) {
  if (!coverage) {
    return statusLine("The coverage of each store's latest audit could not be read. " +
      "Treat an empty or short list as unknown, not as clean.", "medium");
  }
  const counts = {};
  for (const value of Object.values(coverage)) counts[value] = (counts[value] || 0) + 1;
  const partial = (counts.partial || 0) + (counts.unknown || 0);
  const parts = Object.entries(counts).sort(([a], [b]) => a.localeCompare(b))
    .map(([status, n]) => `${number(n)} ${status}`);
  if (!parts.length) {
    return statusLine("No store has a saved audit yet, so there is nothing to list. That is not zero risk.", "medium");
  }
  const lead = `Latest audits: ${parts.join(", ")}.`;
  return statusLine(partial
    ? `${lead} A store whose audit did not cover its whole scope can hold more than is listed; ` +
      "an empty filter is not a clean result, and detection alone does not establish compliance."
    : `${lead} Detection alone does not establish compliance.` +
      (scope === "all" ? " Rows from older runs may predate these audits." : ""),
    partial ? "medium" : "info");
}

// Severity and case counts that are also the quickest filters. Each strip
// counts under every other filter but its own, so picking a chip never makes
// the other chips read zero.
//
// The severity strip is severitySummary's strip variant. A facet is the
// server's GROUP BY over the whole filtered list, so a severity it leaves out
// matched no row: that is a measured zero, filled in here. Only a facet that
// could not be read at all (null) is unknown, and the strip says so.
function severityStrip(counts, {exact = "", min = "", onPick}) {
  const measured = counts && typeof counts === "object"
    ? Object.fromEntries(severityOrder.map(sev => [sev, Number(counts[sev] || 0)])) : null;
  return severitySummary(measured, {
    variant: "strip", onPick,
    active: sev => exact === sev || Boolean(min && severityMeets(sev, min)),
    title: sev => exact === sev ? `Showing only ${sev}; select again to clear` : `Show only ${sev}`,
  });
}

function caseStrip(counts, {active = "", onPick}) {
  const chip = name => {
    const n = Number((counts || {})[name] || 0);
    const on = active === name;
    return h("button", {
      class: `fsum-chip fsum-case${on ? " is-on" : ""}`, type: "button",
      "aria-pressed": String(on), disabled: !n && !on,
      title: CASE_CLAIM_NOTE[name] ? `${caseLabel(name)}: ${CASE_CLAIM_NOTE[name]}` : `Show ${caseLabel(name)} cases`,
      onclick: () => onPick(name),
    }, h("span", {class: "fsum-n"}, number(n)), h("span", {class: "fsum-k"}, caseLabel(name)));
  };
  const lifecycle = h("div", {class: "fsum-group", role: "group", "aria-label": "Filter by case state"},
    h("span", {class: "fsum-label"}, "Case"));
  if (!counts) {
    lifecycle.append(h("span", {class: "sub"}, "Counts unavailable"));
    return [lifecycle];
  }
  CASE_LIFECYCLE.forEach((name, i) => {
    if (i) lifecycle.append(h("span", {class: "fsum-arrow", "aria-hidden": "true"}, "→"));
    lifecycle.append(chip(name));
  });
  const others = CASE_OTHER.filter(name => Number(counts[name] || 0) || active === name);
  const other = h("div", {class: "fsum-group fsum-other", role: "group", "aria-label": "Other case outcomes"},
    h("span", {class: "fsum-label"}, "Claims"),
    others.length ? others.map(chip) : h("span", {class: "sub"}, "None recorded."),
    h("span", {class: "sub fsum-note"},
      "False positive, duplicate and risk accepted each carry a reason; none of them is a fix."));
  return [lifecycle, other];
}

// One helper for a compact time cell: relative, with the exact instant on hover.
function whenCell(value) {
  const millis = toMillis(value);
  if (!Number.isFinite(millis)) return h("span", {class: "sub"}, "-");
  const iso = new Date(millis).toISOString();
  return h("time", {class: "when-short", datetime: iso, title: `${localTime(value)} (${iso})`},
    relativeTime(value));
}

// The most rows one export carries (FINDINGS_EXPORT_CAP in api/app.py).
const FINDINGS_EXPORT_CAP = 50000;

async function renderFindings() {
  await loadCore();
  const box = h("div", {class: "findings-page"});
  box.append(pageHeader("findings",
    "What assessments observed, and what your team decided about each. A finding is an observation, not a verdict."));
  box.append(pageIntro("findings", {
    steps: [
      "New: a run recorded it and nobody has looked yet.",
      "Triaged, then assigned: someone agreed it needs work, and it has an owner.",
      "In progress: the change is under way. Actions proposes tagging, quarantine, or redaction.",
      "Awaiting verification: the change is made; a later run, or a written statement, has to confirm it.",
      "Verified, then closed: a named run confirmed it, and the case is done with a reason.",
      "Or it ends on a claim: false positive, duplicate, or risk accepted. Each needs a reason, " +
        "none is a fix, and any of them can be reopened. Suppression hides a finding; it is not a case state.",
    ],
    actions: [introAction("What could be done about them", "play", () => goTo("actions")),
              introAction("Known-benign calibration", "funnel", () => goTo("falsepositives"))],
  }));

  // Filters live in the URL, so a triage view can be sent to a colleague.
  const filters = {
    q: param("q"), store: param("store"), collection: param("collection"),
    severity: param("severity"), min_severity: param("min_severity"),
    case: param("case"), category: param("category"), owner: param("owner"),
  };
  // Triage order by default: the worst first. The server breaks ties by id.
  let sort = FINDING_SORT_KEYS.includes(param("sort")) ? param("sort") : "severity";
  let dir = param("dir") === "asc" ? "asc" : "desc";
  // What the list counts. "Open now" is each store's latest audit, distinct
  // findings, as Home counts them; "All recorded" is every finding every run
  // wrote, re-runs included. Latest is the default, so an old link without a
  // scope, or one from Home or an audit's next steps, reads as open now.
  let scope = param("scope") === "all" ? "all" : "latest";
  const categories = new Set(filters.category ? [filters.category] : []);

  const search = textInput(filters.q, {placeholder: "Search titles, evidence, ids, fingerprints",
                                       "aria-label": "Search findings"});
  const severitySelect = selectInput([
    ["", "Any severity"], ...severityOrder.map(s => [s, `${s[0].toUpperCase()}${s.slice(1)} only`]),
    ...["high", "medium", "low"].map(s => [`${s}+`, `${s[0].toUpperCase()}${s.slice(1)} and above`]),
  ], filters.severity || (filters.min_severity ? `${filters.min_severity}+` : ""), {ariaLabel: "Severity"});
  const store = selectInput([["", "All stores"], ...state.stores.map(s => [s.store_id, s.store_id])],
                            filters.store, {ariaLabel: "Store"});
  const caseState = selectInput([["", "Any case state"],
                                 ...[...CASE_LIFECYCLE, ...CASE_OTHER].map(k => [k, caseLabel(k)])],
                                filters.case, {ariaLabel: "Case state"});
  const category = selectInput([["", "Any category"], ...[...categories].map(c => [c, categoryLabel(c)])],
                               filters.category, {ariaLabel: "Category"});
  const owner = textInput(filters.owner, {placeholder: "Owner (exact)", "aria-label": "Owner"});
  const count = h("span", {class: "result-count", role: "status"}, "");
  const selection = new Set();
  const out = h("div", {class: "findings-out"});
  const summary = h("div", {class: "fsum", "aria-label": "Counts by severity and case state"});
  const caveat = h("div", {class: "fsum-caveat"});
  const chips = h("div", {class: "active-filters", hidden: true});

  const showSuppressed = h("input", {type: "checkbox", checked: param("suppressed") === "1",
                                     "aria-label": "Show suppressed findings"});
  const suppressedToggle = h("label", {class: "switch-line compact"}, showSuppressed, "Show suppressed");
  const scopeSwitch = segmented({label: "Which findings", value: scope, dataKey: "scope",
    options: [["latest", "Open now (latest audits)"], ["all", "All recorded (every run)"]],
    onPick: value => {
      scope = value;
      suppressedToggle.hidden = scope !== "latest";
      draw(0);
    }});
  suppressedToggle.hidden = scope !== "latest";
  showSuppressed.addEventListener("change", () => draw(0));

  // On a phone the selects fold behind one button; the search stays in view.
  const filterBox = h("div", {class: "ftools-filters", id: "findings-filters"},
    severitySelect, store, caseState, category, owner, suppressedToggle);
  const filterToggle = h("button", {class: "btn ftools-toggle", type: "button",
                                    "aria-expanded": "false", "aria-controls": "findings-filters",
                                    onclick: () => {
                                      const open = filterToggle.getAttribute("aria-expanded") !== "true";
                                      filterToggle.setAttribute("aria-expanded", String(open));
                                      filterBox.classList.toggle("is-open", open);
                                    }}, icon("funnel"), "Filters");

  function readControls() {
    filters.q = search.value.trim();
    const sev = severitySelect.value || "";
    filters.severity = sev.endsWith("+") ? "" : sev;
    filters.min_severity = sev.endsWith("+") ? sev.slice(0, -1) : "";
    filters.store = store.value;
    filters.case = caseState.value;
    filters.category = category.value;
    filters.owner = owner.value.trim();
  }

  function writeControls() {
    search.value = filters.q;
    severitySelect.value = filters.severity || (filters.min_severity ? `${filters.min_severity}+` : "");
    store.value = filters.store;
    caseState.value = filters.case;
    category.value = filters.category;
    owner.value = filters.owner;
  }

  function query({offset = 0, limit = 50, omit = []} = {}) {
    const q = new URLSearchParams();
    q.set("scope", scope);
    // Open now matches Home: suppressed findings are counted apart there, so
    // they are left out here unless asked for. They are tagged, not deleted.
    if (scope === "latest" && !showSuppressed.checked) q.set("suppressed", "false");
    const add = (key, value) => { if (value && !omit.includes(key)) q.set(key, value); };
    add("search", filters.q);
    add("severity", filters.severity);
    add("min_severity", filters.min_severity);
    add("store", filters.store);
    add("collection", filters.collection);
    add("case_state", filters.case);
    add("category", filters.category);
    add("owner", filters.owner);
    q.set("sort", sort);
    q.set("direction", dir);
    q.set("limit", String(limit));
    q.set("offset", String(offset));
    return q.toString();
  }

  // Export takes the list exactly as filtered, without its page size. The
  // server sends no evidence and logs every export.
  let lastTotal = null;
  async function exportFindings(format) {
    const q = new URLSearchParams(query());
    q.delete("limit");
    q.delete("offset");
    q.set("format", format);
    try {
      const body = await api(`/admin/findings/export?${q}`);
      const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
      const filename = `vecshield-findings-${stamp}.${format}`;
      const text = typeof body === "string" ? body : JSON.stringify(body, null, 2);
      if (!downloadText(text, filename, format === "csv" ? "text/csv" : "application/json", "Findings export")) return;
      if (lastTotal != null && lastTotal > FINDINGS_EXPORT_CAP) {
        toast(`Export is partial: ${number(FINDINGS_EXPORT_CAP)} of ${number(lastTotal)} findings. Narrow the filters.`, "warn");
      }
    } catch (e) {
      toast(`Export failed: ${unavailableReason(e)}`, "err");
    }
  }
  // On a phone the word folds away and the icon stays; the button keeps its
  // name, because the word is only hidden from sight.
  const exportToggle = h("button", {class: "btn ftools-export", type: "button", "aria-haspopup": "menu",
                                    "aria-expanded": "false"}, icon("file"),
                         h("span", {class: "ftools-export-text"}, "Export"));
  const exportMenu = popupMenu(exportToggle, [
    {label: "CSV (spreadsheet)", glyph: "file", onclick: () => exportFindings("csv")},
    {label: "JSON", glyph: "code", onclick: () => exportFindings("json")},
  ]);

  // What is narrowing the list, each removable on its own.
  const FILTER_CHIPS = [
    ["q", "Search"], ["severity", "Severity"], ["min_severity", "Severity"], ["store", "Store"],
    ["collection", "Collection"], ["case", "Case"], ["category", "Category"], ["owner", "Owner"],
  ];
  function activeChips() {
    const active = FILTER_CHIPS.filter(([key]) => filters[key]);
    const folded = active.filter(([key]) => key !== "q").length;
    filterToggle.replaceChildren(icon("funnel"), folded ? `Filters (${folded})` : "Filters");
    chips.hidden = !active.length;
    if (!active.length) { chips.replaceChildren(); return; }
    chips.replaceChildren(
      h("span", {class: "sub"}, "Filtered by"),
      ...active.map(([key, label]) => {
        const value = key === "min_severity" ? `${filters[key]} and above`
          : key === "case" ? caseLabel(filters[key]) : filters[key];
        return h("button", {class: "filter-chip", type: "button",
                            "aria-label": `Remove filter ${label}: ${value}`,
                            onclick: () => { filters[key] = ""; writeControls(); draw(0); }},
          h("span", {class: "filter-chip-k"}, `${label}:`), h("span", {class: "filter-chip-v"}, value),
          icon("close"));
      }),
      h("button", {class: "link filter-clear", type: "button", onclick: clearAll}, "Clear all"));
  }

  function clearAll() {
    for (const key of Object.keys(filters)) filters[key] = "";
    writeControls();
    draw(0);
  }

  function pickSeverity(sev) {
    const same = filters.severity === sev;
    filters.severity = same ? "" : sev;
    filters.min_severity = "";
    writeControls();
    draw(0);
  }

  function pickCase(name) {
    filters.case = filters.case === name ? "" : name;
    writeControls();
    draw(0);
  }

  // A header click asks for a column (the table works out the direction);
  // the phone's sort control asks for a column and a direction.
  function onSort(key, next) {
    if (next === "asc" || next === "desc") { sort = key; dir = next; }
    else if (sort === key) dir = dir === "desc" ? "asc" : "desc";
    else { sort = key; dir = key === "store" ? "asc" : "desc"; }
    draw(0);
  }

  function syncCategories(facets) {
    const before = categories.size;
    for (const name of Object.keys((facets || {}).category || {})) categories.add(name);
    if (categories.size === before) return;
    const current = category.value;
    category.replaceChildren(...[["", "Any category"], ...[...categories].sort().map(c => [c, categoryLabel(c)])]
      .map(([val, label]) => h("option", {value: val, selected: val === current}, label)));
    category.value = current;
  }

  // Coverage of each store's latest audit, asked for once, alongside the list.
  const coverageReady = api("/admin/estate").then(estate => Array.isArray(estate?.stores)
    ? Object.fromEntries(estate.stores.filter(s => s.last_assessed)
        .map(s => [s.store_id, String((s.coverage || {}).status || "unknown")]))
    : null).catch(() => null);
  findingsCoverageReady = coverageReady;

  let drawing = 0;
  async function draw(offset = 0) {
    const mine = ++drawing;
    readControls();
    setParams({q: filters.q, severity: filters.severity, min_severity: filters.min_severity,
               store: filters.store, collection: filters.collection, case: filters.case,
               category: filters.category, owner: filters.owner,
               sort: sort === "severity" ? "" : sort, dir: dir === "desc" ? "" : dir,
               offset: offset || "",
               scope: scope === "all" ? "all" : "",
               suppressed: scope === "latest" && showSuppressed.checked ? "1" : ""});
    activeChips();
    out.replaceChildren(loadingState("Loading findings"));
    // The strips count under every filter but their own. When their own is
    // not set, the page's facets already are that count.
    const sevOwn = Boolean(filters.severity || filters.min_severity);
    const caseOwn = Boolean(filters.case);
    const [main, sevFacet, caseFacet, coverage] = await Promise.allSettled([
      api(`/admin/findings?${query({offset})}`),
      sevOwn ? api(`/admin/findings?${query({limit: 1, omit: ["severity", "min_severity"]})}`) : null,
      caseOwn ? api(`/admin/findings?${query({limit: 1, omit: ["case_state"]})}`) : null,
      coverageReady,
    ]);
    // A newer draw (the next keystroke) owns the screen now.
    if (mine !== drawing) return;
    findingsCoverage = coverage.value || null;
    caveat.replaceChildren(coverageNote(findingsCoverage, scope));
    if (main.status === "rejected") {
      const e = main.reason;
      count.textContent = "";
      summary.replaceChildren();
      out.replaceChildren(e.status === 409
        ? unavailableState(unavailableReason(e),
            "Findings are read from recorded scan history.")
        : errorState(unavailableReason(e), () => draw(offset)));
      return;
    }
    const result = main.value;
    lastTotal = Number(result.total ?? 0);
    selection.clear();
    syncCategories(result.facets);
    if (scope === "latest") {
      count.textContent = `${number(result.total)} open in the latest audits` +
        (typeof result.stores_never_assessed === "number" && result.stores_never_assessed
          ? ` · ${plural(result.stores_never_assessed, "store")} never assessed` : "");
      count.title = result.note || "";
    } else {
      count.textContent = `${number(result.findings.length)} shown of ` +
        `${number(result.total)} recorded across every run`;
      count.title = "Every finding every run recorded; re-running a scan records its findings again.";
    }
    const facetOf = (own, settled, key) => own
      ? (settled.status === "fulfilled" && settled.value ? (settled.value.facets || {})[key] || {} : null)
      : (result.facets || {})[key] || {};
    summary.replaceChildren(
      severityStrip(facetOf(sevOwn, sevFacet, "severity"),
                    {exact: filters.severity, min: filters.min_severity, onPick: pickSeverity}),
      ...caseStrip(facetOf(caseOwn, caseFacet, "case_state"), {active: filters.case, onPick: pickCase}));
    out.replaceChildren(findingsCaseTable(result, {
      selection, reload: draw, offset, sort, dir, onSort,
      coverage: scope === "latest" ? findingsCoverage : null,
      clearFilters: FILTER_CHIPS.some(([key]) => filters[key]) ? clearAll : null,
    }));
  }

  // Typing waits for a pause, and only the newest request may draw.
  let typing = null;
  const soon = () => {
    globalThis.clearTimeout?.(typing);
    typing = setTimeout(() => draw(0), 250);
  };
  for (const input of [severitySelect, store, caseState, category]) {
    input.addEventListener("change", () => draw(0));
  }
  search.addEventListener("input", soon);
  owner.addEventListener("input", soon);

  // A finding is a destination: #/findings?finding=<id> opens it, so a row in
  // a report or a chat message can point at exactly one observation. The id
  // stays in the URL while the panel is open and leaves when it closes.
  const wanted = param("finding");
  if (wanted) {
    setTimeout(() => {
      openFinding(wanted, () => draw(Number(param("offset", "0")) || 0));
    }, 0);
  }

  // Scope and count first (what the numbers mean), then search and filters,
  // then the severity/case strips and the coverage caveat, then the table.
  box.append(h("div", {class: "findings-toolbar toolbar", role: "search", "aria-label": "Filter findings"},
    h("div", {class: "findings-scope"}, scopeSwitch, count),
    h("div", {class: "findings-tools"},
      h("div", {class: "search-field"}, icon("search"), search),
      filterToggle, filterBox, exportMenu)));
  box.append(chips);
  box.append(h("section", {class: "fsum-band", "aria-label": "Summary"}, summary, caveat));
  box.append(out);

  await draw(Number(param("offset", "0")) || 0);
  return box;
}

// Why a detector fired, how sure it is, and what argues against it. Without
// this a reader has to open the raw evidence to learn that the "secret" is the
// key AWS prints in its own documentation.
function explanationView(finding) {
  const explanations = ((finding.evidence || {}).explanations) || [];
  if (!explanations.length) {
    return statusLine("This detector does not yet explain itself.", "medium");
  }
  const refs = chunkRefs(finding);
  const chunkFor = e => refs.find(r => r.explanations.some(x =>
    x.detector === e.detector && x.start === e.start && x.end === e.end)) || refs[0] || null;
  return h("div", {class: "explanations"}, explanations.map(e => {
    const against = e.counter_signals || [];
    const ref = chunkFor(e);
    return h("div", {class: `explanation${against.length ? " explanation-disputed" : ""}`},
      h("div", {class: "spread"},
        h("div", {},
          h("span", {class: "mono strong"}, e.detector || "unknown"),
          h("span", {class: "sub"}, " matched "),
          ref
            ? h("button", {class: "link mono", type: "button",
                           title: "Open the chunk with this match highlighted",
                           onclick: () => openChunk({store: finding.store, collection: finding.collection,
                                                     chunkId: ref.chunkId, finding})},
                e.matched_preview || "—", " ", icon("eye"))
            : h("span", {class: "sub mono"}, e.matched_preview || "—")),
        stateChip(e.confidence === "likely" ? "ok"
                  : e.confidence === "possible" ? "medium" : "unknown",
                  e.confidence || "uncertain")),
      h("p", {class: "sub"}, e.confidence_reason || ""),
      against.length
        ? h("div", {},
            h("div", {class: "metric-k"}, "What argues against this"),
            h("ul", {class: "limitations"},
              against.map(c => h("li", {}, c.detail || c.code))))
        : h("p", {class: "sub"}, "Nothing recorded argues against this match."));
  }));
}

// "47 findings" is a list to work through. "3 causes across 47 locations" is a
// decision to make three times.
function causeSummary(findings) {
  const causes = new Map();
  for (const finding of findings || []) {
    const explanations = ((finding.evidence || {}).explanations) || [];
    const keys = explanations.length
      ? [...new Set(explanations.map(e => e.detector || "unknown"))]
      : [String((finding.evidence || {}).check || finding.category || "unattributed")];
    for (const key of keys) {
      const cause = causes.get(key) || {cause: key, findings: 0, locations: new Set(),
                                        disputed: 0, worst: "info"};
      cause.findings += 1;
      if (finding.collection) cause.locations.add(finding.collection);
      if (severityMeets(finding.severity, cause.worst)) cause.worst = finding.severity;
      if (explanations.some(e => e.detector === key && (e.counter_signals || []).length)) {
        cause.disputed += 1;
      }
      causes.set(key, cause);
    }
  }
  const rows = [...causes.values()].sort((a, b) => b.findings - a.findings);
  if (!rows.length) return emptyState("No findings to group.");
  return h("div", {},
    statusLine(`${plural(rows.length, "cause")} across ` +
      `${plural(rows.reduce((n, r) => n + r.findings, 0), "finding")}.`, "info"),
    table(["Cause", "Findings", "Collections", "Worst", "Disputed"],
      rows.map(r => h("tr", {},
        h("td", {class: "mono"}, r.cause),
        h("td", {}, number(r.findings)),
        h("td", {}, r.locations.size ? [...r.locations].sort().join(", ") : "store scope"),
        h("td", {}, badge(r.worst)),
        h("td", {}, r.disputed
          ? stateChip("medium", `${number(r.disputed)} with counter-signals`)
          : h("span", {class: "sub"}, "none"))))));
}

// A location, and — in the open-now view — the coverage of the audit it came
// from when that audit did not cover its whole scope.
function findingLocationCell(finding, coverage) {
  const status = coverage ? coverage[storeIdFor(finding.store)] : null;
  const full = [finding.store, finding.collection].filter(Boolean).join(" / ");
  return h("div", {class: "location", title: full || null},
    h("div", {class: "mono"}, storeLabel(finding.store)),
    h("div", {class: "loc-line"},
      h("span", {class: "sub"}, finding.collection || "store scope"),
      status && status !== "complete"
        ? stateChip(status === "partial" ? "medium" : "unknown", status,
            {title: `This store's latest audit had ${status} coverage: it may hold more than is listed.`})
        : ""));
}

const FINDING_COLUMNS = [{sr: "Select"}, "Severity", "Finding", "Confidence", "Location", "Case",
                         "Recorded", {sr: "Actions"}];
const FINDING_SORTABLE = {Severity: "severity", Location: "store", Case: "case_updated_at",
                          Recorded: "created_at"};
// The same orders as the sortable headers, each way round, for the phone's
// sort control (the header row is hidden there).
const FINDING_SORT_CHOICES = [
  ["severity", "desc", "Severity, worst first"],
  ["severity", "asc", "Severity, least severe first"],
  ["created_at", "desc", "Recorded, newest first"],
  ["created_at", "asc", "Recorded, oldest first"],
  ["case_updated_at", "desc", "Case changed, newest first"],
  ["case_updated_at", "asc", "Case changed, oldest first"],
  ["store", "asc", "Location, A to Z"],
  ["store", "desc", "Location, Z to A"],
];

function findingsCaseTable(result, {selection, reload, offset, sort = "", dir = "desc", onSort = null,
                                    coverage = null, clearFilters = null} = {}) {
  const rows = result.findings || [];
  if (!rows.length) {
    return panel("Findings", h("div", {},
      clearFilters
        ? emptyState("No findings match these filters.",
            {action: clearFilters, actionLabel: "Clear all filters"})
        : emptyState("No findings match these filters.",
            can("operator") ? {action: () => goTo("assess"), actionLabel: "Run an assessment"} : {}),
      statusLine("An empty list is not a clean result: it holds only what the latest " +
                 "audits reached and recorded.", "info")));
  }

  // What to do with the ticked rows. It follows the table and sticks to the
  // bottom of the window while the list is in view, so it is in reach from
  // any row without pushing the rows down when it appears. The count is a
  // status, so a screen reader hears each tick change it.
  const picked = h("span", {class: "bulk-count strong", role: "status"});
  const bulkBar = h("div", {class: "bulk-bar", role: "group", "aria-label": "Selected findings", hidden: true},
    picked,
    h("div", {class: "bulk-actions"},
      gated("compliance", h("button", {class: "btn small primary", type: "button",
                   onclick: () => bulkCaseModal([...selection], reload)},
        icon("user"), "Change case")),
      h("button", {class: "btn small", type: "button",
                   onclick: () => { selection.clear(); redraw(); }}, "Clear selection")));
  function refreshBulk() {
    bulkBar.hidden = selection.size === 0;
    const onPage = rows.filter(f => selection.has(f.id)).length;
    all.checked = onPage > 0 && onPage === rows.length;
    all.indeterminate = onPage > 0 && onPage < rows.length;
    allPhone.checked = all.checked;
    allPhone.indeterminate = all.indeterminate;
    picked.textContent = selection.size ? `${number(selection.size)} selected on this page` : "";
  }

  const all = h("input", {type: "checkbox", "aria-label": "Select every finding on this page"});
  all.addEventListener("change", () => {
    for (const f of rows) all.checked ? selection.add(f.id) : selection.delete(f.id);
    redraw();
  });

  // Below 900px each finding is a card and the header row is hidden, and with
  // it the select-all box and the sort buttons. This bar carries both there;
  // on a wide screen it is not shown.
  const allPhone = h("input", {type: "checkbox"});
  allPhone.addEventListener("change", () => {
    for (const f of rows) allPhone.checked ? selection.add(f.id) : selection.delete(f.id);
    redraw();
  });
  const sortPick = onSort
    ? selectInput(FINDING_SORT_CHOICES.map(([key, way, label]) => [`${key} ${way}`, label]),
                  `${sort || "severity"} ${dir}`, {"aria-label": "Sort findings by"})
    : null;
  sortPick?.addEventListener("change", () => {
    const [key, way] = sortPick.value.split(" ");
    onSort(key, way);
  });
  const phoneBar = h("div", {class: "ftable-phone-bar"},
    h("label", {class: "check-row"}, allPhone, "Select all on this page"),
    sortPick ? h("label", {class: "field ftable-sort"}, h("span", {}, "Sort by"), sortPick) : "");

  const open = f => openFinding(f, reload, {siblings: rows});
  // The select-all box heads its column. Sorting is the server's: a header
  // click asks the page to reload in that order.
  const headers = FINDING_COLUMNS.map(name => {
    if (name && typeof name === "object" && name.sr === "Select") {
      return {label: all, srLabel: "Select", className: "c-select"};
    }
    const key = FINDING_SORTABLE[name];
    if (!key || !onSort) return name;
    return {label: name, sortKey: key, defaultDir: key === "store" ? "asc" : "desc",
            title: key === "case_updated_at" ? "Sort by when the case last changed" : undefined};
  });
  const findingTable = dataTable(headers, {tableClass: "ftable", sort: onSort ? {key: sort, dir, onSort} : null});
  function redraw() {
    findingTable.setRows(rows.map(f => {
      const box = h("input", {type: "checkbox", "aria-label": `Select ${f.title || f.id}`,
                              checked: selection.has(f.id)});
      box.addEventListener("change", () => {
        box.checked ? selection.add(f.id) : selection.delete(f.id);
        refreshBulk();
      });
      const kase = f.case || {};
      const row = h("tr", {class: f.suppressed ? "is-suppressed" : null},
        h("td", {class: "c-select"}, hitBox(box)),
        h("td", {class: "c-sev"}, badge(f.severity)),
        h("td", {class: "c-finding"},
          h("button", {class: "link strong f-title", type: "button", title: f.title || null,
                       onclick: () => open(f)},
            f.title || f.id),
          h("div", {class: "f-line", title: f.description || null},
            h("span", {class: "tag", title: f.category || null}, f.category ? categoryLabel(f.category) : "uncategorized"),
            f.suppressed ? stateChip("medium", "suppressed",
              {title: "Tagged by a suppression. It is still listed; suppression is not a fix."}) : "",
            h("span", {class: "sub f-desc"}, f.description || ""))),
        h("td", {class: "c-conf"}, confidenceCell(f)),
        h("td", {class: "c-loc"}, findingLocationCell(f, coverage)),
        h("td", {class: "c-case"}, caseBadge(kase.state),
          h("div", {class: "sub c-owner", title: kase.owner || null}, kase.owner || "unassigned"),
          CASE_CLAIM_NOTE[kase.state] ? h("div", {class: "sub"}, CASE_CLAIM_NOTE[kase.state]) : ""),
        h("td", {class: "c-when"}, whenCell(f.created_at)),
        h("td", {class: "c-actions"}, rowActions(null, [
          {label: "Open", glyph: "eye", onclick: () => open(f)},
          can("compliance") ? {label: "Change case", glyph: "edit", onclick: () => caseModal(f, reload)} : null,
          {label: "What could be done", glyph: "play",
           onclick: () => goTo("actions", {store: storeIdFor(f.store), finding: f.id})},
        ])));
      return row;
    }));
    refreshBulk();
  }
  redraw();

  const range = `${number(offset + 1)}–${number(offset + rows.length)} of ${number(result.total)}`;
  const pager = (where) => h("div", {class: `bar fpager fpager-${where}`},
    h("span", {class: "sub"}, `Showing ${range}`),
    h("button", {class: "btn small", type: "button", disabled: offset <= 0,
                 "aria-label": "Previous page",
                 onclick: () => reload(Math.max(0, offset - result.limit))}, "Previous"),
    h("button", {class: "btn small", type: "button", disabled: !result.has_more,
                 "aria-label": "Next page",
                 onclick: () => reload(result.next_offset)}, "Next"));

  // The list first: it is what the screen is for. Grouping by cause and the
  // label heatmap are ways of reading the same page, so they follow, folded.
  return h("div", {class: "findings-list"},
    panel("Findings", h("div", {},
      phoneBar,
      findingTable.node,
      bulkBar,
      pager("bottom")), pager("top"), {className: "findings-panel"}),
    foldedPanel("Group by cause", causeSummary(rows)),
    foldedPanel("Where the labels sit", labelMatrix(rows, {reload})));
}

// One visible action per row; the rest behind a "More actions" menu. A
// destructive item is last, marked, and never sits at the same weight as the
// row's primary action. The menu is a real menu: it opens on click, Escape or a
// click elsewhere closes it and returns focus, and the arrow keys move within
// it. It is positioned against the viewport so a scrolling table cannot clip it.
let openRowMenu = null;

function closeRowMenu({focus = false} = {}) {
  const current = openRowMenu;
  openRowMenu = null;
  current?.close({focus});
}

function rowActions(primary, items = []) {
  const entries = items.filter(Boolean);
  if (!entries.length) return h("div", {class: "row-actions"}, primary || "");
  const toggle = h("button", {class: "icon-btn row-more", type: "button", "aria-haspopup": "menu",
                              "aria-expanded": "false", "aria-label": "More actions"}, icon("more"));
  return h("div", {class: "row-actions"}, primary || "", popupMenu(toggle, entries));
}

// A toggle and the menu it opens. One open at a time, closed by a click
// elsewhere, a scroll, Escape or Tab; arrow keys move between items. The row
// menu and the account menu in the header are both this.
function popupMenu(toggle, entries) {
  const menu = h("div", {class: "menu-pop", role: "menu", hidden: true});
  const buttons = entries.map(({label, glyph, onclick, danger}) => h("button", {
    class: `menu-item${danger ? " menu-danger" : ""}`, type: "button", role: "menuitem",
    onclick: () => { closeRowMenu(); onclick(); },
  }, glyph ? icon(glyph) : "", label));
  menu.append(...buttons);
  const self = {
    close({focus = false} = {}) {
      menu.hidden = true;
      toggle.setAttribute("aria-expanded", "false");
      if (focus) toggle.focus?.();
    },
  };
  toggle.addEventListener("click", event => {
    event?.stopPropagation?.();
    if (!menu.hidden) { closeRowMenu({focus: true}); return; }
    closeRowMenu();
    menu.hidden = false;
    toggle.setAttribute("aria-expanded", "true");
    const rect = toggle.getBoundingClientRect?.();
    if (rect && menu.style) {
      // Below the toggle, or above it when the room below is too short for
      // the menu and there is more above (the last rows of a list on a
      // phone). It scrolls inside the room it has, and keeps 8px from either
      // side of the window.
      const viewH = window.innerHeight || 0;
      const viewW = window.innerWidth || 0;
      const below = viewH - rect.bottom - 12;
      const above = rect.top - 12;
      const up = viewH > 0 && (menu.scrollHeight || 0) > below && above > below;
      const width = menu.offsetWidth || 0;
      let right = Math.max(8, Math.round(viewW - rect.right));
      if (viewW && width) right = Math.max(8, Math.min(right, viewW - width - 8));
      menu.style.position = "fixed";
      menu.style.top = up ? "auto" : `${Math.round(rect.bottom + 4)}px`;
      menu.style.bottom = up ? `${Math.round(viewH - rect.top + 4)}px` : "auto";
      menu.style.right = `${right}px`;
      if (viewH > 0) menu.style.maxHeight = `${Math.max(120, Math.round(up ? above : below))}px`;
    }
    openRowMenu = self;
    buttons[0]?.focus?.();
  });
  menu.addEventListener("keydown", event => {
    const index = buttons.indexOf(document.activeElement);
    if (event?.key === "Escape") {
      event.preventDefault?.();
      event.stopPropagation?.();
      closeRowMenu({focus: true});
    } else if (event?.key === "ArrowDown" || event?.key === "ArrowUp") {
      event.preventDefault?.();
      const step = event.key === "ArrowDown" ? 1 : buttons.length - 1;
      buttons[(Math.max(0, index) + step) % buttons.length]?.focus?.();
    } else if (event?.key === "Tab") {
      closeRowMenu();
    }
  });
  return h("div", {class: "menu-wrap"}, toggle, menu);
}

// A panel whose body starts closed: a second way of reading what is already
// on screen, one click away rather than above the thing itself.
function foldedPanel(title, body) {
  return h("details", {class: "panel panel-fold"},
    h("summary", {class: "panel-title"}, h("h2", {class: "panel-heading"}, title),
      h("span", {class: "sub"}, "Show")),
    h("div", {class: "panel-body"}, body));
}

// Collection × label, from the findings on this page. A cell is chunks the
// classifier labelled, as recorded; an empty cell is "no finding here", not
// "clean", and the caption says which page of results it covers.
function labelMatrix(findings, {reload} = {}) {
  const grid = new Map();
  const labels = new Set();
  for (const f of findings || []) {
    const counts = ((f.evidence || {}).label_counts) || {};
    if (!Object.keys(counts).length) continue;
    const key = `${storeIdFor(f.store)} / ${f.collection || "(store)"}`;
    const row = grid.get(key) || {store: f.store, collection: f.collection, cells: {}, findings: []};
    for (const [label, n] of Object.entries(counts)) {
      row.cells[label] = (row.cells[label] || 0) + Number(n || 0);
      labels.add(label);
    }
    row.findings.push(f);
    grid.set(key, row);
  }
  if (!grid.size) return statusLine("No finding on this page carries labelled chunks.", "info");
  const columns = [...labels].sort();
  const peak = Math.max(1, ...[...grid.values()].flatMap(r => Object.values(r.cells)));
  return h("div", {},
    h("div", {class: "table-wrap"},
      h("table", {class: "matrix"},
        h("thead", {}, h("tr", {}, h("th", {scope: "col"}, "Collection"),
          columns.map(l => h("th", {scope: "col", class: "matrix-col"}, l)))),
        h("tbody", {}, [...grid.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, row]) => h("tr", {},
          h("th", {scope: "row"},
            h("button", {class: "link mono", type: "button",
                         onclick: () => goTo("schema", {store: storeIdFor(row.store), collection: row.collection})},
              key)),
          columns.map(label => {
            const n = row.cells[label] || 0;
            const weight = n ? Math.min(4, 1 + Math.floor((n / peak) * 3)) : 0;
            return h("td", {class: "matrix-cell", "data-label": label},
              n
                ? h("button", {class: `cell-btn heat-${weight}`, type: "button",
                               title: `${plural(n, `${label} chunk`)} in ${row.collection || "the store"}`,
                               onclick: () => labelCellModal(row, label, reload)}, number(n))
                : h("span", {class: "sub"}, "\u00b7"));
          })))))),
    h("p", {class: "sub"}, "Counts are labelled chunks recorded by the findings on this page. " +
      "Click a cell for the findings behind it; click a collection to open it."));
}

function labelCellModal(row, label, reload) {
  const matching = row.findings.filter(f => Number((((f.evidence || {}).label_counts) || {})[label] || 0));
  modal(`${label} in ${row.collection || "the store"}`, h("div", {},
    table(["Severity", "Finding", "Chunks", ""], matching.map(f => h("tr", {},
      h("td", {}, badge(f.severity)),
      h("td", {}, h("div", {class: "strong"}, f.title || f.id), h("div", {class: "sub mono"}, f.id)),
      h("td", {}, number((((f.evidence || {}).label_counts) || {})[label] || 0)),
      h("td", {}, h("button", {class: "btn small", type: "button",
        onclick: () => openFinding(f, reload)}, icon("eye"), "Open")))))),
    null, "Close");
}

// The fields a move needs, marked as the move is chosen. `required` lets the
// browser stop an incomplete claim before the server refuses it; the hint says
// why the field is needed.
function caseMoveFields(toState, owner, reason) {
  const hint = h("p", {class: "sub case-hint", "aria-live": "polite"}, "");
  const sync = () => {
    const to = toState.value;
    reason.required = CASE_NEEDS_REASON.has(to);
    owner.required = to === "assigned";
    hint.textContent = caseMoveHint(to);
  };
  toState.addEventListener("change", sync);
  sync();
  return hint;
}

async function caseModal(finding, reload) {
  let current;
  try {
    current = await api(`/admin/findings/${encodeURIComponent(finding.id)}/case`);
  } catch (e) {
    toast(e.message, "err");
    return;
  }
  const allowed = current.allowed_transitions || [];
  const toState = selectInput([["", "Leave the state unchanged"],
                               ...allowed.map(s => [s, caseLabel(s)])]);
  const owner = textInput(current.owner || "", {placeholder: "owner@example.com"});
  const reason = h("textarea", {placeholder: "Why — required to resolve, accept, close, or verify"});
  const job = textInput("", {placeholder: "run id that confirmed it (for verified)"});
  const hint = caseMoveFields(toState, owner, reason);

  // The decision first; the evidence for it one click away (the panel behind
  // this dialog already shows it in full).
  modal(`Case — ${finding.id}`, h("div", {},
    h("dl", {class: "kv"},
      h("dt", {}, "Finding"), h("dd", {}, finding.title || "-"),
      h("dt", {}, "Current state"), h("dd", {}, caseBadge(current.state)),
      h("dt", {}, "Owner"), h("dd", {}, current.owner || "unassigned"),
      h("dt", {}, "Suppressed"), h("dd", {}, finding.suppressed ? "yes" : "no")),
    field("Move to", toState),
    hint,
    field("Owner", owner),
    field("Reason", reason),
    field("Verified by run", job),
    statusLine("Suppression hides a finding. It is not a case state and never " +
               "means the work was done.", "info"),
    foldedPanel("Why this fired", explanationView(finding)),
    current.events.length
      ? panel("History", table(["When", "Who", "From", "To", "Reason"],
          current.events.map(e => h("tr", {},
            h("td", {}, formatWhen(e.at)), h("td", {}, e.actor),
            h("td", {}, e.from_state), h("td", {}, e.to_state),
            h("td", {}, e.reason || "-")))))
      : statusLine("No case changes recorded yet.", "info")),
    async () => {
      const body = {};
      if (toState.value) body.to_state = toState.value;
      if (owner.value && owner.value !== current.owner) body.owner = owner.value;
      if (reason.value) body.reason = reason.value;
      if (job.value) body.verified_by_job_id = job.value;
      await api(`/admin/findings/${encodeURIComponent(finding.id)}/case`,
                {method: "POST", body: JSON.stringify(body)});
      toast("Case updated.");
      closeModal();
      reload();
    }, "Save case", {stack: true});
}

function bulkCaseModal(ids, reload) {
  const toState = selectInput([["", "Leave the state unchanged"],
                               ...Object.keys(CASE_STATE_TONE).map(s => [s, caseLabel(s)])]);
  const owner = textInput("", {placeholder: "owner@example.com"});
  const reason = h("textarea", {placeholder: "Why — required to resolve, accept, close, or verify"});
  const hint = caseMoveFields(toState, owner, reason);

  modal(`Change ${ids.length} cases`, h("div", {},
    statusLine(`This applies to ${plural(ids.length, "finding")}. Each is evaluated on its own: ` +
               "the ones whose current state does not allow the move are reported back, " +
               "not silently skipped.", "info"),
    field("Move to", toState),
    hint,
    field("Owner", owner),
    field("Reason", reason)),
    async () => {
      const body = {finding_ids: ids};
      if (toState.value) body.to_state = toState.value;
      if (owner.value) body.owner = owner.value;
      if (reason.value) body.reason = reason.value;
      const result = await api("/admin/findings/cases",
                               {method: "POST", body: JSON.stringify(body)});
      closeModal();
      if (result.refused) {
        modal("Bulk change: partial", h("div", {},
          statusLine(`${number(result.applied)} applied, ${number(result.refused)} refused.`,
                     "medium"),
          table(["Finding", "Why it was refused"],
            result.refusals.map(r => h("tr", {},
              h("td", {class: "mono"}, r.finding_id), h("td", {}, r.reason))))),
          null, "Close");
      } else {
        toast(`${plural(result.applied, "case")} updated.`);
      }
      reload();
    }, "Apply to all");
}

async function recentFindings(limit = 50) {
  const r = await api(`/admin/history?limit=${encodeURIComponent(limit)}`);
  const rows = (r.jobs || []).filter(j => Number(j.finding_count || 0) > 0).slice(0, limit);
  const jobs = await Promise.all(rows.map(j => api(`/admin/history/${encodeURIComponent(j.id)}`).catch(() => null)));
  return jobs.filter(Boolean).flatMap(job => (job.findings || []).map(f => ({
    ...f,
    store: f.store || job.store,
    job_id: f.job_id || job.id,
    evidence: typeof f.evidence === "string" ? safeJson(f.evidence) : (f.evidence || {}),
  })));
}

function customizeTemplateModal(t) {
  const name = textInput(t.name || "");
  const action = textInput(t.action || "");
  const severity = selectInput(severityOrder.map(s => [s, s]), t.severity || "high");
  const scopeStore = selectInput([["", "Global / All stores"], ...state.stores.map(s => [s.store_id, s.store_id])]);
  const scopeCollection = collectionControl("Scope collection", "", {placeholder: "optional collection"});
  const description = h("textarea", {}, t.description || "");
  description.value = t.description || "";
  const when = h("textarea", {}, JSON.stringify(t.when || {}, null, 2));
  when.value = JSON.stringify(t.when || {}, null, 2);
  scopeStore.addEventListener("change", () => syncCollectionControl(scopeStore.value, scopeCollection));
  syncCollectionControl(scopeStore.value, scopeCollection);
  modal("Customize template", h("div", {},
    h("div", {class: "grid"}, fieldTip("Name", name, "Policy display name saved in your configured policy list."), fieldTip("Action", action, "Remediation/action identifier attached to matching violations."), fieldTip("Severity", severity, "Default severity assigned to violations created from this policy.")),
    h("div", {class: "grid"}, fieldTip("Scope store", scopeStore, "Leave global to apply across all stores, or scope to one registered connector."), scopeCollection.field),
    fieldTip("Description", description, "Operational guidance shown with this policy."),
    fieldTip("Rule JSON", when, "Editable rule. Supported keys include category, requires_label, min_severity, collection, and evidence_gte."),
    h("div", {class: "rule-line"}, ruleSummary(t.when || {}))),
    async () => {
      const payload = {
        template_id: t.id,
        name: name.value.trim() || t.name,
        description: description.value,
        action: action.value.trim() || t.action,
        severity: severity.value,
        when: JSON.parse(when.value),
        scope_store: scopeStore.value || null,
        scope_collection: scopeCollection.input.value.trim() || null,
      };
      await api("/admin/policies", {method: "POST", body: JSON.stringify(payload)});
      toast("Customized policy created.");
      closeModal();
      route();
    }, "Create policy");
}

// A suppression's end date, and whether it has passed or is close. A lapsed
// suppression no longer tags its finding; one about to lapse will soon stop.
function suppressionExpiry(value) {
  const at = toMillis(value);
  if (!Number.isFinite(at)) return h("span", {class: "sub"}, "No end date recorded");
  const left = at - Date.now();
  return h("div", {class: "fp-expiry"}, formatWhen(value),
    left <= 0 ? stateChip("unknown", "lapsed", {title: "Past its end date: it no longer tags its finding."})
      : left < 7 * 86400000 ? stateChip("medium", "lapses soon", {title: "Ends within 7 days."}) : "");
}

async function renderFalsePositives() {
  const box = h("div", {class: "fp-page"});
  // Swallowing these errors rendered "No records." for a list nobody was
  // allowed to read — a reader would conclude there are no allow-list rules
  // when there may be hundreds. An unreadable list is unavailable, not empty.
  const [allowResult, suppressResult] = await Promise.allSettled([
    api("/admin/allowlist"), api("/admin/suppressions"),
  ]);
  box.append(pageHeader("falsepositives", "Known-benign calibration stays visible; findings are tagged rather than hidden."));

  const rules = allowResult.status === "fulfilled" ? (allowResult.value.allowlist || []) : null;
  const suppressions = suppressResult.status === "fulfilled" ? (suppressResult.value.suppressions || []) : null;
  const builtin = (rules || []).filter(r => (r.source || "custom") === "builtin").length;
  const expiringSoon = (suppressions || []).filter(s =>
    s.expires_at && (toMillis(s.expires_at) - Date.now()) < 7 * 86400000).length;
  box.append(pageIntro("falsepositives", {
    facts: [
      ["Allow-list rules", rules ? number(rules.length) : "?",
       rules ? `${number(builtin)} built-in \u00b7 ${number(rules.length - builtin)} custom` : "unavailable"],
      ["Suppressions", suppressions ? number(suppressions.length) : "?",
       suppressions ? (expiringSoon ? `${number(expiringSoon)} lapse within 7 days` : "time-boxed") : "unavailable"],
    ],
    actions: [
      introAction("Findings, including tagged ones", "alert", () => goTo("findings")),
      introAction("Detector thresholds", "sliders", () => goTo("detectors")),
    ],
  }));

  // Each list counts itself in its heading, as the Actions queues do; a list
  // that could not be read has no count, because it has no known length.
  box.append(panel(rules ? `Allow-list (${number(rules.length)})` : "Allow-list", allowResult.status === "rejected"
    ? unavailableState(unavailableReason(allowResult.reason),
        "The allow-list could not be read, so this is not a list of none.")
    : table(["Reason", "Scope", "Rule", "Source"],
        rules.map(r => h("tr", {},
          h("td", {class: "fp-reason"}, r.reason),
          h("td", {}, [r.store, r.collection].filter(Boolean).join(" / ") || "Global / All stores"),
          h("td", {class: "mono"}, r.rule || "-"),
          h("td", {}, h("span", {class: "tag"}, (r.source || "custom") === "builtin" ? "built-in" : r.source || "custom")))),
        {tableClass: "fp-table"})));

  box.append(panel(suppressions ? `Suppressions (${number(suppressions.length)})` : "Suppressions",
    suppressResult.status === "rejected"
    ? unavailableState(unavailableReason(suppressResult.reason),
        "Suppressions could not be read, so this is not a list of none.")
    : table(["Fingerprint", "Reason", "Owner", "Expires"],
        suppressions.map(s => h("tr", {},
          h("td", {class: "mono fp-print", title: s.fingerprint || null}, s.fingerprint),
          h("td", {class: "fp-reason"}, s.reason),
          h("td", {}, s.owner || h("span", {class: "sub"}, "unassigned")),
          h("td", {}, suppressionExpiry(s.expires_at)))),
        {tableClass: "fp-table"})));
  return box;
}

const RUNTIME_LIMIT = 200;

// A rule by the detector name the Detectors screen uses, with its id below
// for searching and for the filter; a rule the console does not know shows
// its id alone.
function runtimeRuleCell(rule) {
  const known = DETECTOR_UI.find(d => d.key === rule);
  if (!known) return h("span", {class: "mono"}, rule || "unknown");
  return h("div", {}, h("div", {}, known.name), " ", h("div", {class: "sub mono"}, rule));
}

async function renderRuntime() {
  const box = h("div", {class: "runtime-page"});
  const sev = selectInput([["", "All severities"], ...severityOrder.map(s => [s, severityName(s)])], "",
                          {"aria-label": "Severity"});
  const rule = textInput("", {type: "search", placeholder: "Rule", "aria-label": "Rule"});
  const principal = textInput("", {type: "search", placeholder: "Principal", "aria-label": "Principal"});
  const count = h("span", {class: "result-count", role: "status"}, "");
  const summary = h("div", {});
  const alertsTable = dataTable(["Severity", "Rule", "Principal", "Collection", "Message"],
                                {wrapClass: "table-wrap runtime-table"});
  const listNote = h("div", {});
  const listBody = h("div", {class: "runtime-list"});
  const filtered = () => Boolean(sev.value || rule.value.trim() || principal.value.trim());
  let seq = 0;
  const load = async () => {
    const at = ++seq;
    const params = new URLSearchParams({limit: String(RUNTIME_LIMIT)});
    if (sev.value) params.set("severity", sev.value);
    if (rule.value.trim()) params.set("rule", rule.value.trim());
    if (principal.value.trim()) params.set("principal", principal.value.trim());
    let stats, alerts;
    try {
      [stats, alerts] = await Promise.all([api("/runtime/alerts/stats"), api(`/runtime/alerts?${params}`)]);
    } catch (e) {
      if (at !== seq) return;
      // A failed read is not an empty list: say so, and offer the retry.
      count.textContent = "";
      summary.replaceChildren();
      listBody.replaceChildren(errorState(unavailableReason(e), load));
      return;
    }
    if (at !== seq) return;
    // The server counts alerts grouped by severity, so a severity it leaves
    // out had none; only a missing breakdown is unknown.
    const bySeverity = stats.by_severity && typeof stats.by_severity === "object"
      ? Object.fromEntries(severityOrder.map(s => [s, stats.by_severity[s] || 0])) : null;
    summary.replaceChildren(severitySummary(bySeverity, {columns: true, total: stats.total,
                                                         sub: "Persisted alerts, by severity."}));
    const rows = alerts.alerts || [];
    count.textContent = `${plural(rows.length, "alert")} shown`;
    alertsTable.setRows(rows.map(a => h("tr", {},
      h("td", {}, badge(a.severity)), h("td", {}, runtimeRuleCell(a.rule)), h("td", {}, a.principal),
      h("td", {}, a.collection), h("td", {}, a.message))),
      {empty: filtered() ? "No alert matches these filters." : "No alerts have been recorded."});
    listNote.replaceChildren(rows.length >= RUNTIME_LIMIT
      ? statusLine(`Showing the latest ${number(RUNTIME_LIMIT)}. Narrow the filters to see older alerts.`, "info")
      : "");
    listBody.replaceChildren(listNote, alertsTable.node);
  };
  sev.addEventListener("change", load);
  const apply = h("button", {class: "btn", type: "submit"}, icon("refresh"), "Refresh");
  const tools = toolbar("Filter alerts", h("form", {class: "runtime-tools",
    onsubmit: event => { event?.preventDefault?.(); load(); }},
    sev, rule, principal, apply, count));
  box.append(pageHeader("runtime", "Persisted alerts from the live monitor.",
    gated("operator", h("button", {class: "btn primary", type: "button", onclick: runtimeEventModal},
      icon("play"), "Send test event"))));
  box.append(summary, panel("Alerts", [tools, listBody]));
  await load();
  return box;
}

function runtimeEventModal() {
  const principal = textInput("service-account");
  const collection = collectionControl("Collection", "kb-docs");
  const resultCount = textInput("120", {type: "number"});
  loadCore().then(() => allKnownCollections()).then(names => collection.setCollections(names)).catch(() => {});
  modal("Send runtime event", h("div", {class: "grid"}, field("Principal", principal), collection.field, field("Result count", resultCount)), async () => {
    const r = await api("/runtime/events", {method: "POST", body: JSON.stringify({principal: principal.value, collection: collection.input.value, result_count: Number(resultCount.value) || 0, result_ids: []})});
    toast(`Event processed. Alerts raised: ${(r.alerts || []).length}.`, (r.alerts || []).length ? "err" : "ok");
    closeModal();
    route();
  });
}

// Detectors: four runtime rules over forwarded query events, each explained
// in the reader's terms, tuned one at a time, and saved deliberately.
//
// Field ranges mirror _validate_detector_settings in api/config_store.py; the
// server still validates, and a refusal is shown on the field it names. Values
// the reader has not touched go back exactly as they came, so a percentage
// shown for a fraction cannot drift on a save of something else.
//
// "Enabled in configuration" is all a toggle says. Nothing here reads whether a
// detector is ready (warmed up, supplied with collection sizes, receiving query
// vectors), so the prerequisites are stated instead of inferred.
const DETECTOR_UI = [
  {
    key: "bulk_volume", name: "Bulk querying",
    summary: "One principal sends a large number of queries in a short time.",
    why: "Copying a store's content out through its search API takes many queries. A burst of volume from one account is the plainest sign of it.",
    measures: "This counts queries, not the records they returned.",
    prerequisite: "",
    fields: [
      {key: "threshold", label: "Query count", unit: "queries", kind: "int", min: 1,
       help: "Alert when one principal reaches this many queries inside the time window."},
      {key: "window_s", label: "Time window", unit: "seconds", kind: "float", min: 0, minOpen: true,
       help: "The rolling window the queries are counted over."},
    ],
    advanced: [],
    rule: v => `Alert at ${severityName(v.severity)} when one principal sends ${detNum(v.threshold)} queries within ${detDuration(v.window_s)}.`,
    example: v => `A reporting service account sends ${detNum(v.threshold)} queries between 09:00 and ${detClock(v.window_s)}. Query number ${detNum(v.threshold)} raises a ${severityName(v.severity)} alert.`,
  },
  {
    key: "collection_sweep", name: "Collection harvesting",
    summary: "One principal retrieves a large share of one collection's records.",
    why: "Many small, ordinary-looking queries can still walk an entire collection. Counting the distinct records returned catches what query volume alone misses.",
    measures: "This counts distinct record IDs returned from one collection, against that collection's size.",
    prerequisite: "Needs the IDs of the records each query returned (clients must forward them) and each collection's size. The console's default runtime engine has no source for collection sizes, so with it this detector never alerts, even when enabled. A deployment that supplies its own engine may provide one.",
    fields: [
      {key: "fraction", label: "Share of the collection", unit: "%", kind: "percent", min: 0, max: 100,
       help: "Alert when one principal's queries have returned at least this share of a collection's distinct records."},
      {key: "window_s", label: "Time window", unit: "seconds", kind: "float", min: 0, minOpen: true,
       help: "The rolling window the distinct records are counted over."},
    ],
    advanced: [],
    rule: v => `Alert at ${severityName(v.severity)} when one principal retrieves ${detNum(detPercent(v.fraction))}% or more of a collection's distinct records within ${detDuration(v.window_s)}.`,
    example: v => `A principal's queries return ${detNum(Math.ceil(Number(v.fraction) * 10000))} distinct records from a 10,000-record collection within ${detDuration(v.window_s)}. That raises a ${severityName(v.severity)} alert, if the engine knows the collection holds 10,000.`,
  },
  {
    key: "enumeration", name: "Repeated similar queries",
    summary: "One principal sends a run of near-identical query vectors.",
    why: "Nudging a query vector in small steps maps out what a store holds, one neighbourhood at a time. People rarely send almost the same query many times in a row.",
    measures: "This compares each query vector with the principal's previous one.",
    prerequisite: "Only events that include the query vector are checked; clients must forward it.",
    fields: [
      {key: "run_length", label: "Consecutive similar queries", unit: "queries", kind: "int", min: 1,
       help: "Alert when this many queries in a row are each similar to the one before."},
      {key: "max_gap_s", label: "Maximum gap between queries", unit: "seconds", kind: "float", min: 0,
       help: "A longer pause between two queries ends the run."},
    ],
    advanced: [
      {key: "sim_threshold", label: "Cosine similarity", unit: "from -1 to 1", kind: "float", min: -1, max: 1,
       help: "How alike two consecutive query vectors must be to count as a repeat. 1 means the same direction; lower values count looser matches and alert more often."},
    ],
    rule: v => `Alert at ${severityName(v.severity)} after ${detNum(v.run_length)} consecutive queries from one principal, each at least ${detNum(v.sim_threshold)} cosine-similar to the one before and no more than ${detDuration(v.max_gap_s)} after it.`,
    example: v => `A script sends ${detNum(v.run_length)} queries a few seconds apart, each vector shifted slightly from the last. Query number ${detNum(v.run_length)} raises a ${severityName(v.severity)} alert.`,
  },
  {
    key: "rate_baseline", name: "Query-rate spikes",
    summary: "A principal's query rate jumps well above its own normal.",
    why: "Some abuse stays under any fixed threshold but is still far from normal for that particular account.",
    measures: "This compares a principal's query count in the current window with a baseline learned from its own earlier windows.",
    prerequisite: "Learns each principal's normal rate from its own traffic, and cannot alert for a principal until it has taken the warm-up samples (one per time window). Baselines are held in memory.",
    fields: [
      {key: "spike_factor", label: "Spike multiplier", unit: "× baseline", kind: "float", min: 0, minOpen: true,
       help: "Alert when the current window's count is at least this many times the learned baseline."},
      {key: "window_s", label: "Time window", unit: "seconds", kind: "float", min: 0, minOpen: true,
       help: "Queries are counted per window, and the baseline is sampled once per window."},
      {key: "min_rate", label: "Minimum queries per window", unit: "queries", kind: "float", min: 0,
       help: "Below this count nothing alerts, however large the multiple, so a quiet account going from 1 to 6 queries is not a spike."},
    ],
    advanced: [
      {key: "warmup_samples", label: "Warm-up samples", unit: "windows", kind: "int", min: 0,
       help: "How many windows of a principal's traffic to learn from before it can alert."},
      {key: "alpha", label: "Smoothing", unit: "above 0, up to 1", kind: "float", min: 0, minOpen: true, max: 1,
       help: "How quickly the baseline follows recent traffic. Higher values adapt faster; lower values remember longer."},
    ],
    rule: v => `Alert at ${severityName(v.severity)} when a principal sends at least ${detNum(v.min_rate)} queries in ${detDuration(v.window_s)} and that is ${detNum(v.spike_factor)}× or more its learned baseline, once ${plural(v.warmup_samples, "warm-up window")} ${Number(v.warmup_samples) === 1 ? "has" : "have"} been observed.`,
    example: v => `An account that usually sends about 20 queries in a ${detDuration(v.window_s)} window sends ${detNum(Math.max(Number(v.min_rate) || 0, 20 * (Number(v.spike_factor) || 0)))} in one window. That raises a ${severityName(v.severity)} alert.`,
  },
];

const DETECTOR_COOLDOWN = {key: "cooldown_s", label: "Repeat-alert cooldown", unit: "seconds", kind: "float", min: 0,
  help: "After an alert, further alerts for the same principal and detector within this time are folded into the first rather than sent again. 0 sends every one."};

function detNum(value) {
  const n = Number(value);
  return Number.isFinite(n) ? new Intl.NumberFormat(undefined, {maximumFractionDigits: 4}).format(n) : "?";
}

function detPercent(fraction) {
  return Number((Number(fraction) * 100).toPrecision(12));
}

function detDuration(seconds) {
  const s = Number(seconds);
  if (!Number.isFinite(s)) return "? seconds";
  if (s >= 3600 && s % 3600 === 0) return plural(s / 3600, "hour");
  if (s >= 60 && s % 60 === 0) return plural(s / 60, "minute");
  return plural(s, "second");
}

function detClock(seconds) {
  const total = Math.round(9 * 3600 + (Number(seconds) || 0));
  const hh = String(Math.floor(total / 3600) % 24).padStart(2, "0");
  const mm = String(Math.floor(total / 60) % 60).padStart(2, "0");
  const ss = total % 60;
  return ss ? `${hh}:${mm}:${String(ss).padStart(2, "0")}` : `${hh}:${mm}`;
}

// What the field shows for a stored value, and the stored value a typed string
// means. A value the reader has not edited is never parsed back.
function detectorDisplay(spec, value) {
  if (value == null || value === "") return "";
  return spec.kind === "percent" ? String(detPercent(value)) : String(value);
}

function detectorParse(spec, raw) {
  const text = String(raw ?? "").trim();
  if (!text) return {error: "Enter a value."};
  if (spec.kind === "int" && !/^-?\d+$/.test(text)) return {error: "Enter a whole number."};
  const n = Number(text);
  if (!Number.isFinite(n)) return {error: "Enter a number."};
  const unit = spec.kind === "percent" ? "%" : "";
  if (spec.min != null && (spec.minOpen ? n <= spec.min : n < spec.min)) {
    return {error: spec.minOpen ? `Must be more than ${spec.min}${unit}.` : `Must be ${spec.min}${unit} or more.`};
  }
  if (spec.max != null && n > spec.max) return {error: `Must be ${spec.max}${unit} or less.`};
  return {value: spec.kind === "percent" ? n / 100 : n};
}

// Leaving a screen with unsaved edits asks first. route() consults this before
// it tears the page down; the browser's own prompt covers closing the tab.
let leaveGuard = null;

function confirmLeave(target) {
  const stay = h("button", {class: "btn", type: "button", onclick: closeModal}, "Stay and keep editing");
  const leave = h("button", {class: "btn danger", type: "button", onclick: () => {
    leaveGuard = null;
    closeModal();
    location.hash = target;
  }}, "Discard changes and leave");
  modal("Discard unsaved changes?", h("p", {}, leaveGuard?.message || "This page has changes that have not been saved."),
    null, "", {actions: [stay, leave]});
}

async function renderDetectors() {
  // Unreadable configuration is an error with a retry (route() renders it),
  // never an editable form filled with assumed defaults.
  const loaded = await api("/admin/detectors");
  const clone = value => JSON.parse(JSON.stringify(value || {}));
  let saved = clone(loaded);
  let draft = clone(loaded);
  let raw = {};
  let errors = {};
  let saving = false;
  let serverError = "";
  // When the principal is known a non-admin sees the settings read only. With
  // no principal (no token entered yet) the console cannot tell; the server decides.
  let readOnly = !can("admin");
  let selected = DETECTOR_UI.some(d => d.key === param("detector")) ? param("detector") : DETECTOR_UI[0].key;

  const pathsOf = det => [...det.fields, ...det.advanced].map(f => `${det.key}.${f.key}`)
    .concat([`${det.key}.enabled`, `${det.key}.severity`]);
  const allPaths = () => DETECTOR_UI.flatMap(pathsOf).concat(["cooldown_s"]);
  const read = (obj, path) => path.split(".").reduce((cur, part) => (cur == null ? undefined : cur[part]), obj);
  const write = (obj, path, value) => {
    const parts = path.split(".");
    let cur = obj;
    for (const part of parts.slice(0, -1)) cur = (cur[part] ||= {});
    cur[parts[parts.length - 1]] = value;
  };
  const changed = () => allPaths().filter(p => read(draft, p) !== read(saved, p));
  const invalid = () => Object.keys(errors);
  const sectionState = key => ({
    dirty: changed().some(p => p.startsWith(`${key}.`)),
    bad: invalid().some(p => p.startsWith(`${key}.`)),
  });

  const box = h("div", {class: "detectors"});
  box.append(pageHeader("detectors", "Configure alerts for unusual query activity.",
    h("button", {class: "btn", type: "button", onclick: () => goTo("runtime")}, icon("alert"), "View runtime alerts")));
  box.append(h("div", {class: "detector-scope"},
    h("p", {class: "muted"},
      "These rules watch query events that clients forward to the runtime monitor, and raise alerts on the Runtime screen. " +
      "A principal is the user or service account making the queries. Checks for sensitive text are on ",
      h("button", {class: "link", type: "button", onclick: () => goTo("ingest")}, "Ingest"), ".")));
  if (readOnly) {
    box.append(statusLine("Administrator access is required to edit these settings. You can read them here.", "info"));
  }

  const list = h("div", {class: "detector-list", role: "list", "aria-label": "Detectors"});
  const detail = h("section", {class: "panel detector-detail", "aria-labelledby": "detector-title"});
  const cooldownBox = h("div", {});
  const saveBar = h("div", {class: "save-bar", role: "region", "aria-label": "Unsaved detector changes"});
  box.append(h("div", {class: "detector-layout"}, list, detail));
  box.append(panel("Alert frequency", cooldownBox));
  box.append(saveBar);

  function control(spec, path) {
    const id = `det-${path.replace(".", "-")}`;
    const helpId = `${id}-help`;
    const errorId = `${id}-error`;
    if (!(path in raw)) raw[path] = detectorDisplay(spec, read(draft, path));
    const input = textInput(raw[path], {
      id, type: "text", inputmode: spec.kind === "int" ? "numeric" : "decimal",
      "aria-describedby": `${helpId} ${errorId}`, disabled: readOnly || saving,
    });
    const errorLine = h("p", {class: "field-error", id: errorId});
    const syncError = () => {
      errorLine.textContent = errors[path] || "";
      errors[path] ? input.setAttribute("aria-invalid", "true") : input.removeAttribute("aria-invalid");
    };
    input.addEventListener("input", () => {
      raw[path] = input.value;
      const parsed = detectorParse(spec, input.value);
      if (parsed.error) errors[path] = parsed.error;
      else { delete errors[path]; write(draft, path, parsed.value); }
      serverError = "";
      syncError(); drawList(); drawRule(); drawSaveBar();
    });
    syncError();
    return h("div", {class: "field detector-field"},
      h("label", {for: id}, h("span", {}, spec.label)),
      h("div", {class: "input-unit"}, input, h("span", {class: "unit"}, spec.unit)),
      h("p", {class: "sub", id: helpId}, spec.help),
      errorLine);
  }

  function drawList() {
    list.replaceChildren(...DETECTOR_UI.map(det => {
      const on = read(draft, `${det.key}.enabled`);
      const st = sectionState(det.key);
      return h("div", {role: "listitem"}, h("button", {
        class: `detector-choice${det.key === selected ? " is-selected" : ""}`, type: "button",
        "aria-current": det.key === selected ? "true" : null,
        onclick: () => select(det.key),
      },
        h("span", {class: "strong"}, det.name),
        h("span", {class: "sub"}, det.summary),
        h("span", {class: "tag-row"},
          on === true ? stateChip("info", "enabled in configuration", {glyph: "check"})
            : on === false ? stateChip("unknown", "disabled in configuration")
            : stateChip("unknown", "not reported"),
          st.bad ? stateChip("critical", "invalid value") : st.dirty ? stateChip("medium", "unsaved changes") : "")));
    }));
  }

  const ruleBox = h("div", {class: "detector-rule"});
  function drawRule() {
    const det = DETECTOR_UI.find(d => d.key === selected);
    const values = draft[det.key] || {};
    const missing = pathsOf(det).filter(p => read(draft, p) == null);
    ruleBox.replaceChildren(
      missing.length
        ? statusLine(`The server did not report ${plural(missing.length, "setting")} for this detector, so its rule cannot be described.`, "unknown")
        : h("div", {},
            h("h3", {}, "Current rule"),
            h("p", {}, det.rule(values)),
            h("h3", {}, "Example"),
            h("p", {class: "muted"}, det.example(values)),
            h("p", {class: "sub"}, "Illustrative, and it follows the values above as you edit. It is not a recommended threshold for every workload, and it says nothing about how well the detector performs.")));
  }

  function drawDetail() {
    const det = DETECTOR_UI.find(d => d.key === selected);
    const enabled = h("input", {type: "checkbox", id: "det-enabled", disabled: readOnly || saving,
      checked: read(draft, `${det.key}.enabled`) === true});
    enabled.addEventListener("change", () => {
      write(draft, `${det.key}.enabled`, enabled.checked);
      serverError = "";
      drawList(); drawSaveBar();
    });
    const sevPath = `${det.key}.severity`;
    const current = read(draft, sevPath);
    const severity = selectInput(
      [...(severityOrder.includes(current) ? [] : [["", "Not reported"]]), ...severityOrder.map(v => [v, severityName(v)])],
      severityOrder.includes(current) ? current : "", {id: "det-severity", disabled: readOnly || saving, "aria-describedby": "det-severity-help"});
    severity.addEventListener("change", () => {
      if (severity.value) write(draft, sevPath, severity.value);
      serverError = "";
      drawList(); drawRule(); drawSaveBar();
    });
    drawRule();
    detail.replaceChildren(
      h("div", {class: "panel-title"}, h("h2", {class: "panel-heading", id: "detector-title"}, det.name)),
      h("div", {class: "panel-body"},
        h("p", {}, det.summary, " ", h("span", {class: "muted"}, det.measures)),
        h("p", {class: "muted"}, h("strong", {}, "Why this matters: "), det.why),
        h("label", {class: "check-row", for: "det-enabled"}, enabled, h("span", {}, "Enabled in configuration")),
        det.prerequisite ? statusLine(det.prerequisite, "info") : "",
        h("div", {class: "detector-fields"},
          det.fields.map(spec => control(spec, `${det.key}.${spec.key}`)),
          h("div", {class: "field detector-field"},
            h("label", {for: "det-severity"}, h("span", {}, "Alert severity")),
            severity,
            h("p", {class: "sub", id: "det-severity-help"}, "The severity each alert from this detector carries."))),
        det.advanced.length
          ? h("details", {class: "evidence-data detector-advanced", open: det.advanced.some(spec => errors[`${det.key}.${spec.key}`]) || null},
              h("summary", {}, icon("sliders"), "Advanced settings"),
              h("div", {class: "detector-fields"}, det.advanced.map(spec => control(spec, `${det.key}.${spec.key}`))))
          : "",
        ruleBox));
  }

  function drawCooldown() {
    cooldownBox.replaceChildren(h("div", {class: "detector-fields detector-fields-narrow"}, control(DETECTOR_COOLDOWN, "cooldown_s")),
      h("p", {class: "sub"}, "Applies to every detector."));
  }

  const saveStatus = h("span", {class: "save-status", role: "status"});
  function drawSaveBar() {
    if (readOnly) { saveBar.hidden = true; return; }
    const count = changed().length;
    const bad = invalid();
    saveBar.classList.toggle("is-active", count > 0 || bad.length > 0 || saving);
    saveStatus.textContent = saving ? "Saving…"
      : bad.length ? `Fix ${plural(bad.length, "invalid value")} before saving.`
      : count ? `${plural(count, "unsaved change")}`
      : "No unsaved changes";
    saveBar.replaceChildren(
      h("div", {class: "save-bar-text"}, saveStatus,
        serverError ? h("p", {class: "field-error"}, serverError) : "",
        h("p", {class: "sub"}, "Saving rebuilds the default runtime engine, which clears its rolling windows, learned baselines, and cooldowns.")),
      h("div", {class: "save-bar-actions"},
        h("button", {class: "btn", type: "button", disabled: (!count && !bad.length) || saving, onclick: discard}, "Discard changes"),
        h("button", {class: "btn primary", type: "button", disabled: !count || bad.length > 0 || saving,
          "aria-busy": String(saving), onclick: save}, "Save changes")));
  }

  function redraw() { drawList(); drawDetail(); drawCooldown(); drawSaveBar(); }

  function select(key) {
    selected = key;
    setParams({detector: key === DETECTOR_UI[0].key ? "" : key});
    drawList(); drawDetail();
    // The list is redrawn, so focus goes back to the choice just made.
    list.querySelector(".detector-choice.is-selected")?.focus?.();
  }

  function discard() {
    draft = clone(saved);
    raw = {};
    errors = {};
    serverError = "";
    redraw();
    announce("Changes discarded. Showing the saved settings.");
  }

  async function save() {
    if (saving || !changed().length || invalid().length) return;
    saving = true;
    serverError = "";
    // The returned server configuration replaces the draft. Freeze controls
    // during that request so later keystrokes cannot be silently overwritten.
    box.querySelectorAll("input, select").forEach(input => { input.disabled = true; });
    drawSaveBar();
    try {
      const next = await api("/admin/detectors", {method: "PUT", body: JSON.stringify(draft)});
      saved = clone(next);
      draft = clone(next);
      raw = {};
      errors = {};
      toast("Detector settings saved.");
      announce("Detector settings saved.");
    } catch (e) {
      if (e.status === 401 || e.status === 403) {
        serverError = "Your account cannot save detector settings; administrator access is required. Your changes are still here.";
      } else {
        const message = e.message || "The settings could not be saved.";
        const path = allPaths().find(p => message.includes(p));
        if (path) errors[path] = message.replace(path, "").replace(/^\s*/, "Server: ");
        serverError = `Not saved: ${message}. Your changes are still here.`;
      }
      announce(serverError);
    } finally {
      saving = false;
      redraw();
    }
  }

  leaveGuard = {
    view: "detectors",
    message: "Your detector changes have not been saved. Leaving discards them.",
    dirty: () => (changed().length > 0 || invalid().length > 0) && !readOnly,
  };
  redraw();
  return box;
}

// Alert delivery. Webhooks are edited as rows, not as JSON. The API masks
// every secret: a Slack or PagerDuty URL comes back as its scheme and host
// ("https://hooks.slack.com/…") and a routing key as "***". A row left as it
// came is sent back exactly as it came, and the server swaps the stored secret
// back in, so saving a severity change can never replace a real URL with its
// mask. A new or replaced URL must be a full http(s) address.
const WEBHOOK_STYLES = [["slack", "Slack"], ["pagerduty", "PagerDuty (Events v2)"], ["generic", "Generic JSON"]];

function isMaskedUrl(url) {
  return url === "***" || /\/…$/.test(String(url || ""));
}

function webhookProblems(rows) {
  const problems = [];
  rows.forEach((row, index) => {
    const n = index + 1;
    const url = row.url.trim();
    if (!url) problems.push(`Webhook ${n}: a URL is required.`);
    else if (!isMaskedUrl(url) && !/^https?:\/\/[^\s/]+/i.test(url)) {
      problems.push(`Webhook ${n}: "${url}" is not an http(s) URL.`);
    }
    if (row.style === "pagerduty" && !row.routing_key) {
      problems.push(`Webhook ${n}: PagerDuty needs a routing key.`);
    }
  });
  return problems;
}

async function renderAlerting() {
  const a = await api("/admin/alerting");
  const enabled = h("input", {type: "checkbox", checked: a.enabled});
  const consoleSink = h("input", {type: "checkbox", checked: a.console});
  const min = selectInput(severityOrder.map(sev => [sev, `${severityName(sev)} or above`]), a.min_severity || "high", {"aria-label": "Minimum severity"});
  const list = h("div", {class: "webhooks"});
  const errors = h("div", {});
  const rows = [];

  function addRow(hook = {url: "", style: "slack"}) {
    const masked = isMaskedUrl(hook.url);
    const url = textInput(hook.url || "", {placeholder: "https://hooks.slack.com/services/…",
                                           "aria-label": `Webhook ${rows.length + 1} URL`});
    const style = selectInput(WEBHOOK_STYLES, hook.style || "slack", {"aria-label": `Webhook ${rows.length + 1} style`});
    const keyMasked = hook.routing_key === "***";
    const key = textInput("", {placeholder: keyMasked ? "Stored key kept; type to replace" : "Routing key",
                               "aria-label": `Webhook ${rows.length + 1} routing key`});
    const keyField = field("Routing key", key);
    const row = {hook, url, style, key, keyMasked, node: null};
    const syncKey = () => { keyField.hidden = style.value !== "pagerduty"; };
    style.addEventListener("change", syncKey);
    syncKey();
    row.node = h("div", {class: "webhook-row"},
      field("URL", url), field("Style", style), keyField,
      h("button", {class: "btn small", type: "button", "aria-label": "Remove this webhook", onclick: () => {
        rows.splice(rows.indexOf(row), 1);
        row.node.remove();
      }}, icon("trash"), "Remove"),
      masked ? h("p", {class: "sub webhook-note"}, "The full URL is stored on the server and shown masked. " +
                                                   "Leave it as it is to keep it; type a new URL to replace it.") : "");
    rows.push(row);
    list.append(row.node);
  }
  (a.webhooks || []).forEach(addRow);

  function collect() {
    return rows.map(row => {
      const entry = {url: row.url.value.trim(), style: row.style.value};
      if (row.style.value === "pagerduty") {
        const typed = row.key.value.trim();
        if (typed) entry.routing_key = typed;
        else if (row.keyMasked) entry.routing_key = "***";
      }
      return entry;
    });
  }

  async function save() {
    const webhooks = collect();
    const problems = webhookProblems(webhooks);
    if (problems.length) {
      errors.replaceChildren(h("div", {class: "state state-error form-errors", role: "alert"},
        icon("sev-critical"), h("ul", {}, problems.map(p => h("li", {}, p)))));
      return;
    }
    errors.replaceChildren();
    try {
      await api("/admin/alerting", {method: "PUT", body: JSON.stringify({
        enabled: enabled.checked, console: consoleSink.checked, min_severity: min.value, webhooks})});
      toast("Alerting updated.");
      route();
    } catch (e) {
      errors.replaceChildren(errorState(`The server refused this configuration: ${unavailableReason(e)}`));
    }
  }

  return h("div", {},
    pageHeader("alerting", "Where audit and runtime alerts are delivered. Webhook secrets stay masked.",
      h("button", {class: "btn primary", type: "button", onclick: save}, "Save alerting")),
    panel("Delivery", h("div", {class: "form-stack"},
      h("label", {class: "check-row"}, enabled, h("span", {}, "Enabled")),
      h("label", {class: "check-row"}, consoleSink, h("span", {}, "Console sink")),
      field("Minimum severity", min))),
    panel("Webhooks", h("div", {},
      list,
      rows.length ? "" : h("p", {class: "sub"}, "No webhook is configured."),
      h("button", {class: "btn small", type: "button", onclick: () => addRow()}, icon("plus"), "Add webhook"))),
    errors);
}

// How an erasure was established, not merely that it was. Re-enumerating a
// collection is the one check a soft delete is guaranteed to fool, so a reader
// needs to see which checks actually ran: a pass on enumeration alone is a
// weaker statement than one that also re-read the ids and replayed the deleted
// vectors, and the difference is exactly where ghost vectors hide.
const ERASURE_METHODS = {
  enumeration: "the subject appears in no listed chunk",
  id_reread: "the deleted ids are no longer returned when addressed directly",
  retrieval_replay: "each deleted chunk's own stored vector no longer retrieves it",
};

function erasureVerification(store) {
  const v = (store.execution && store.execution.verification) || null;
  const methods = (v && v.methods) || [];
  const ghosts = (v && v.ghost_hits) || [];
  const limits = (v && v.method_limitations) || [];
  const box = h("div", {class: "verification"});

  box.append(h("p", {class: "sub"},
    `Erased ${plural(store.chunks_deleted, "chunk")}. ` +
    (ghosts.length
      ? "The store still serves chunks it reported deleted."
      : store.verified
        ? "Verified by the checks below."
        : "Verification did not confirm the deletion.")));

  if (methods.length) {
    box.append(h("ul", {class: "checklist"}, ...methods.map(m =>
      h("li", {}, h("strong", {}, m.replace(/_/g, " ")), " — ",
        ERASURE_METHODS[m] || "recorded on the verification"))));
  }

  // A ghost is enumeration and retrieval disagreeing: the record is hidden from
  // the listing and still answering. That is a failed erasure, not a caveat.
  ghosts.forEach(hit => box.append(statusLine(
    `Still served: ${hit.collection}/${hit.chunk_id} (${String(hit.method).replace(/_/g, " ")}). ` +
    (hit.detail || ""), "error")));

  // What could not be checked is stated, because a check that never ran must
  // not read as a check that passed.
  limits.forEach(text => box.append(statusLine(`Not checked: ${text}`, "medium")));

  return box;
}

// pending | scanned | executed | awaiting_verification | partial_error. Only
// "executed" has finished erasing, and only with verification. "scanned" says
// nothing about whether anything matched, so the state a reader sees is
// derived from the counts as well: a scan that matched nothing is not "matches
// found", and one that could not search a store is not finished.
const DSAR_STATUS = {
  pending: {tone: "unknown", text: "scan not run"},
  scanned: {tone: "low", text: "matches found, nothing erased"},
  executed: {tone: "ok", text: "erased and verified"},
  awaiting_verification: {tone: "medium", text: "erased, awaiting verification"},
  partial_error: {tone: "critical", text: "partly failed"},
};

function dsarState(d) {
  const status = String(d?.status || "");
  const found = Number(d?.total_chunks_found || 0);
  const errors = Number(Array.isArray(d?.stores)
    ? d.stores.filter(s => s.error || s.coverage_complete === false).length
    : d?.stores_with_errors || 0);
  if (status === "scanned") {
    if (errors) return {tone: "medium", text: "search incomplete", open: true};
    if (found) return {...DSAR_STATUS.scanned, open: true};
    return {tone: "info", text: "no match in searched scope", open: false};
  }
  const meta = DSAR_STATUS[status] || {tone: "unknown", text: status || "unknown"};
  return {...meta, open: status !== "executed"};
}

function dsarChip(statusOrRequest) {
  const d = typeof statusOrRequest === "object" && statusOrRequest ? statusOrRequest : {status: statusOrRequest};
  const meta = dsarState(d);
  return stateChip(meta.tone, meta.text);
}

// What a privacy request is, said on the screen rather than folded away: the
// three steps, and the limits a DPO has to know before relying on a result.
function privacyHowItWorks() {
  const step = (n, title, text) => h("li", {class: "privacy-step"},
    h("span", {class: "privacy-step-n"}, n),
    h("span", {}, h("span", {class: "strong"}, title), h("span", {class: "sub"}, text)));
  return h("section", {class: "privacy-how", "aria-label": "How a privacy request works"},
    h("ol", {class: "privacy-steps"},
      step("1", "Find", "Every chosen store is searched, read-only, for chunks whose text or metadata contain the person's identifier."),
      step("2", "Review", "Open each match, masked, to confirm it concerns this person. Nothing has changed yet."),
      step("3", "Delete and verify", COMPLIANCE_COPY.dsar.stepErase)),
    h("p", {class: "privacy-limits sub"}, icon("info"),
      "A match is an identifier found in stored text or metadata, not every mention of the person. " +
      "A store that could not be searched in full proves nothing. Erasure here does not reach backups, the source " +
      "systems the chunks came from, or copies elsewhere, and the evidence it produces is not a legal conclusion."));
}

async function renderDSAR() {
  // The store list feeds the new-request picker; a failure there must not hide
  // the requests themselves.
  try { await loadCore(); } catch { /* the picker says there are no stores */ }
  const requestId = param("request");
  if (requestId) return privacyRequestView(requestId);
  const r = await api("/admin/dsar");
  const requests = r.dsars || [];
  const open = requests.filter(d => dsarState(d).open).length;
  const matched = requests.reduce((sum, d) => sum + Number(d.total_chunks_found || 0), 0);
  const show = selectInput([["", "All requests"], ["open", "Needs action"], ["closed", "Closed"]],
                           param("show"), {"aria-label": "Show"});
  const count = h("span", {class: "result-count"}, "");
  const requestTable = dataTable(["Subject", "State", "Requested", "Stores searched", "Matched", "Erased", {sr: "Open"}]);
  function draw() {
    const list = requests.filter(d => !show.value || (show.value === "open") === dsarState(d).open);
    count.textContent = `${number(list.length)} of ${plural(requests.length, "request")}`;
    requestTable.setRows(list.map(d => h("tr", {class: "privacy-row"},
      h("td", {class: "mono"}, d.subject),
      h("td", {}, dsarChip(d)),
      h("td", {}, formatWhen(d.requested_at)),
      h("td", {}, number(d.stores_scanned ?? 0),
        Number(d.stores_with_errors || 0)
          ? h("span", {class: "sub"}, ` · ${number(d.stores_with_errors)} incomplete`) : ""),
      h("td", {}, number(d.total_chunks_found)),
      h("td", {}, number(d.total_chunks_deleted || 0)),
      h("td", {}, h("button", {class: "btn small", type: "button", "aria-label": `Open the request for ${d.subject}`,
                               onclick: () => openPrivacyRequest(d.id)}, "Open")))),
    {empty: "No request matches this filter."});
  }
  show.addEventListener("change", () => { setParams({show: show.value}); draw(); });
  draw();
  return h("div", {class: "privacy-view"},
    pageHeader("dsar", COMPLIANCE_COPY.dsar.header,
      gated("compliance", h("button", {class: "btn primary", type: "button", onclick: dsarModal}, icon("plus"), "New request"))),
    pageIntro("dsar", {
      facts: [
        ["Requests", number(requests.length)],
        ["Needs action", number(open), requests.length ? "matched, incomplete or not yet verified" : ""],
        ["Chunks matched", number(matched), "across all requests"],
      ],
      actions: [
        introAction("GDPR erasure criteria", "check", () => goTo("criteria", {framework: "GDPR"})),
        introAction("CCPA deletion criteria", "check", () => goTo("criteria", {framework: "CCPA/CPRA"})),
        introAction("Stores in scope", "db", () => goTo("stores")),
      ],
    }),
    privacyHowItWorks(),
    requests.length
      ? panel("Requests", h("div", {},
          h("div", {class: "privacy-filters"}, show, count),
          requestTable.node))
      : panel("Requests", emptyState("No requests have been opened. A request searches read-only first; nothing is deleted until you say so.",
                                     can("compliance") ? {action: dsarModal, actionLabel: "Open a request"} : {})));
}

// One request opens as its own page (`#/dsar?request=<id>`), so it can be
// linked, and erasure is decided on a page rather than in a dialog.
function openPrivacyRequest(id) {
  goTo("dsar", {request: id});
}

function erasedAllIn(store, collection) {
  const deleted = Number(((store.execution || {}).deleted || {})[collection] || 0);
  const matched = (store.impact?.matches || []).filter(m => m.collection === collection).length;
  return deleted > 0 && deleted >= matched;
}

async function privacyRequestView(id) {
  const box = h("div", {class: "privacy-view privacy-detail"});
  // The request is named by its subject once it has loaded, and by its id
  // until then (or when it cannot be read).
  const header = title => pageHeader(title, "One person's request: where they were found, and what was deleted.", null,
    {back: {label: "All requests", className: "archive-back", onclick: () => climbOut("dsar")}});
  let d;
  try { d = await api(`/admin/dsar/${encodeURIComponent(id)}`); }
  catch (e) {
    box.append(header(recordTitle("Request", id)),
      panel(`Request ${id}`, errorState(unavailableReason(e), () => route())));
    return box;
  }
  box.append(header(d.subject ? h("span", {class: "mono"}, d.subject) : recordTitle("Request", d.id || id)));
  const stores = d.stores || [];
  const found = Number(d.total_chunks_found || 0);
  const incomplete = stores.filter(s => s.error || s.coverage_complete === false);
  const erasable = ["scanned", "partial_error", "awaiting_verification"].includes(d.status) && found > 0;
  const executedLike = ["executed", "awaiting_verification", "partial_error"].includes(d.status);
  const state = dsarState(d);

  const guidance = d.status === "pending"
    ? statusLine("The search has not run yet.", "medium")
    : d.status === "executed"
      ? statusLine("Deletion has run and was verified. Each store below says which checks showed it.", "ok")
      : d.status === "awaiting_verification"
        ? statusLine("Deletions were acknowledged but not yet verified. Run the deletion again to verify them; nothing is deleted twice.", "medium")
        : d.status === "partial_error"
          ? statusLine("Deletion did not finish in every store. The stores below say what failed; running it again retries only those.", "error")
          : found
            ? statusLine(fillCopy(COMPLIANCE_COPY.dsar.readOnly, {matches: plural(found, "match", "matches")}), "info")
            : incomplete.length
              ? statusLine("Nothing matched in the stores that could be searched, but not every store could be. That is not evidence of absence.", "medium")
              : statusLine("No chunk in the searched stores contains this identifier. There is nothing to delete there.", "info");

  box.append(recordHead({
    meta: [
      stateChip(state.tone, state.text),
      h("span", {class: "sub"}, "requested"), formatWhen(d.requested_at),
      d.executed_at ? [h("span", {class: "sub"}, COMPLIANCE_COPY.dsar.erasedWhen), formatWhen(d.executed_at)] : "",
      h("span", {class: "mono sub"}, d.id || id)],
    action: h("dl", {class: "privacy-totals"},
      h("div", {}, h("dt", {}, "Stores searched"), h("dd", {}, number(stores.length))),
      h("div", {}, h("dt", {}, "Matched"), h("dd", {}, number(found))),
      h("div", {}, h("dt", {}, "Erased"), h("dd", {}, number(d.total_chunks_deleted || 0)))),
    notes: [
      guidance,
      incomplete.length
        ? statusLine(`${plural(incomplete.length, "store")} could not be searched in full (${incomplete.map(s => s.store_id).join(", ")}). ` +
                     "Deletion skips them; open a new request once they can be searched.", "medium")
        : "",
      d.notes ? h("p", {class: "sub"}, `Notes: ${d.notes}`) : "",
      d.error ? statusLine(d.error, "error") : ""],
  }));

  box.append(panel("Stores", table(["Store", "Search", "Matched", "Erased", "Verified", "Notes"],
    stores.map(s => h("tr", {},
      h("td", {class: "mono"}, s.store_id),
      h("td", {}, coverageChip(s.coverage_complete ? "complete" : (s.impact ? (s.impact.coverage_status || "partial") : "unavailable"))),
      h("td", {}, number(s.chunks_found || 0)),
      h("td", {}, number(s.chunks_deleted || 0)),
      h("td", {}, s.execution
        ? stateChip(s.verified ? "ok" : "medium", s.verified ? "verified" : "not verified")
        : h("span", {class: "sub"}, Number(s.chunks_found || 0) ? "not erased" : "nothing to erase")),
      h("td", {}, s.error ? h("span", {class: "error-text"}, s.error)
        : (s.impact?.limitations || []).join(" ") || h("span", {class: "sub"}, "-")))))));

  for (const store of stores.filter(s => (s.impact?.matches || []).length || s.execution)) {
    const matches = store.impact?.matches || [];
    box.append(panel(`${store.store_id} · ${plural(store.chunks_found, "match", "matches")}`, h("div", {},
      matches.length
        ? table(["Chunk", "Collection", "Matched on", "Preview", {sr: "Open"}],
            matches.map(m => h("tr", {},
              h("td", {class: "mono"}, m.chunk_id),
              h("td", {}, m.collection),
              h("td", {}, m.matched_on),
              h("td", {class: "mono sub"}, m.preview || ""),
              // An erased chunk cannot be fetched; offering to open it would
              // only produce an error. Deletions are counted per collection,
              // so only a collection whose every match was deleted says so.
              h("td", {}, erasedAllIn(store, m.collection)
                ? h("span", {class: "sub"}, "erased")
                : h("button", {class: "btn small", type: "button",
                    onclick: () => openChunk({store: store.store_id, collection: m.collection, chunkId: m.chunk_id})},
                    icon("eye"), "Open")))))
        : "",
      store.execution ? erasureVerification(store) : "",
      store.execution
        ? h("div", {class: "bar"}, h("button", {class: "btn small", type: "button",
            onclick: () => showErasureReceipts(store.store_id)}, icon("list"), "Erasure receipts"))
        : "")));
  }

  const actions = h("div", {class: "privacy-actions"});
  if (executedLike) {
    actions.append(h("div", {class: "bar"},
      h("button", {class: "btn", type: "button", onclick: () => downloadErasureEvidence(d.id || id)},
        icon("file"), "Download erasure evidence"),
      h("span", {class: "sub"}, "The request, what was matched and erased per store, and how each deletion was verified.")));
  }
  const blocker = erasable ? await dsarExecuteBlocker(d) : "";
  if (erasable && blocker) {
    actions.append(h("div", {class: "bar privacy-erase"},
      h("button", {class: "btn danger", type: "button", disabled: true, "aria-disabled": "true", title: blocker},
        icon("trash"), d.status === "scanned" ? COMPLIANCE_COPY.dsar.erase : COMPLIANCE_COPY.dsar.retry),
      h("span", {class: "gated-why dsar-blocker"}, icon("lock"), blocker)));
  } else if (erasable) {
    const outcome = h("div", {});
    actions.append(h("div", {class: "bar privacy-erase"},
      h("button", {class: "btn danger", type: "button", onclick: async () => {
        // Only an explicit yes proceeds. The old window.confirm?.() check
        // treated "no dialog available" (undefined) as consent.
        const ok = await confirmAction({
          title: "Erase this subject's chunks?",
          message: `${plural(found, "chunk")} that reference ${d.subject} ` +
                   `will be deleted from ${plural(stores.filter(s => s.chunks_found).length, "store")}. This cannot be undone. ` +
                   "Verification runs afterwards and is recorded with the request.",
          confirmLabel: "Erase chunks", danger: true,
          typed: String(d.subject || id), typedLabel: "To confirm, type the subject ",
        });
        if (ok !== true) return;
        try {
          await api(`/admin/dsar/${encodeURIComponent(d.id || id)}/execute`,
                    {method: "POST", body: JSON.stringify({verify: true})});
          toast(COMPLIANCE_COPY.dsar.erased);
          route();
        } catch (e) {
          outcome.replaceChildren(refusalLine(e, COMPLIANCE_COPY.dsar.failed));
        }
      }}, icon("trash"), d.status === "scanned" ? COMPLIANCE_COPY.dsar.erase : COMPLIANCE_COPY.dsar.retry),
      h("span", {class: "sub"}, "Explicit, logged, and verified three ways where the connector allows it.")),
      outcome);
  }
  if (actions.children.length) box.append(panel("Erasure", actions));
  box.append(h("details", {class: "evidence-data"}, h("summary", {}, icon("code"), "Request data"), jsonBlock(d)));
  return box;
}

// Why this reader may not execute this request's erasure, or "" when they
// may. Erasure needs the compliance role, and a second person: whoever opened
// the request cannot also erase it, unless they are an admin or this
// deployment has separation of duties off. The server applies the same rule.
async function dsarExecuteBlocker(d) {
  if (!can("compliance")) return roleNeed("compliance");
  const me = state.auth.user?.username;
  if (!me || isAdmin()) return "";
  let author = d.created_by || d.requested_by || "";
  // The request list carries who opened each request; a detail without it
  // is completed from there rather than guessed.
  if (!author && d.id) {
    try { author = ((await api("/admin/dsar")).dsars || []).find(x => x.id === d.id)?.created_by || ""; }
    catch { author = ""; }
  }
  if (!author || author !== me) return "";
  const policy = await approvalsPolicy();
  if (policy.separation_of_duties === "off") return "";
  return COMPLIANCE_COPY.dsar.blocker;
}

// Stores are picked from the registry, not typed. None ticked means every
// store, which is said in words rather than left implied.
function dsarModal() {
  const subject = textInput("", {placeholder: "an email, a name, or an account id", required: true});
  const notes = textInput("", {placeholder: "optional: ticket number, requester, deadline"});
  const boxes = (state.stores || []).map(s => ({id: s.store_id,
    input: h("input", {type: "checkbox", value: s.store_id, "aria-label": `Scan ${s.store_id}`})}));
  const scopeNote = h("p", {class: "sub"}, "No store ticked: every registered store is scanned.");
  const sync = () => {
    const n = boxes.filter(b => b.input.checked).length;
    scopeNote.textContent = n ? `${number(n)} of ${plural(boxes.length, "store")} will be scanned.`
                              : "No store ticked: every registered store is scanned.";
  };
  boxes.forEach(b => b.input.addEventListener("change", sync));
  modal("New privacy request", h("div", {},
    statusLine(COMPLIANCE_COPY.dsar.newRequest, "info"),
    field("Subject", subject),
    h("p", {class: "sub"}, "The exact identifier is searched for in chunk text and metadata. Use the value your stores hold " +
      "(an email address finds that address, not the person's name)."),
    h("fieldset", {class: "store-picks"}, h("legend", {}, "Stores"),
      boxes.length
        ? boxes.map(b => h("label", {class: "check-row"}, b.input, h("span", {class: "mono"}, b.id)))
        : h("p", {class: "sub"}, "No stores are registered."),
      scopeNote),
    field("Notes", notes)), async () => {
    if (!subject.value.trim()) throw new Error("Name the data subject.");
    const ids = boxes.filter(b => b.input.checked).map(b => b.id);
    const created = await api("/admin/dsar", {method: "POST", body: JSON.stringify({subject: subject.value.trim(), store_ids: ids.length ? ids : null, notes: notes.value})});
    toast("Request opened; the read-only search has run.");
    closeModal();
    if (created?.id) openPrivacyRequest(created.id);
    else route();
  }, "Open request");
}

// The proof a privacy team hands on: the request's evidence bundle, and each
// store's erasure receipts, which are read back from the hash-chained log.
async function downloadErasureEvidence(id) {
  try {
    const bundle = await api(`/admin/dsar/${encodeURIComponent(id)}/evidence`);
    downloadText(JSON.stringify(bundle, null, 2),
      `vecshield-erasure-evidence-${String(id).replace(/[^a-zA-Z0-9_-]/g, "_")}.json`,
      "application/json", `Erasure evidence — ${id}`);
  } catch (e) { toast(unavailableReason(e), "err"); }
}

async function showErasureReceipts(storeId) {
  const body = h("div", {}, loadingState("Reading the erasure receipts"));
  modal(`Erasure receipts — ${storeId}`, body, null, "Close", {stack: true});
  try {
    const r = await api(`/stores/${encodeURIComponent(storeId)}/erasure/receipts`);
    const receipts = r.receipts || [];
    body.replaceChildren(
      r.chain_verified
        ? statusLine("Read back from the audit log, whose hash chain verifies.", "ok")
        : statusLine(`The audit log's hash chain does not verify: ${r.chain_reason || "unknown reason"}. ` +
                     "These receipts cannot be relied on as proof.", "error"),
      receipts.length
        ? table(["When", "By", "Receipt"], receipts.map(x => h("tr", {},
            h("td", {}, formatWhen(x.timestamp)),
            h("td", {}, x.actor || "-"),
            h("td", {}, kvList(Object.fromEntries(Object.entries(x).filter(([k]) => !["timestamp", "actor"].includes(k))),
                               {limit: 8})))))
        : emptyState("No erasure has been recorded for this store."),
      h("div", {class: "bar"}, h("button", {class: "btn small", type: "button",
        onclick: () => downloadText(JSON.stringify(r, null, 2),
          `vecshield-erasure-receipts-${String(storeId).replace(/[^a-zA-Z0-9_-]/g, "_")}.json`,
          "application/json", `Erasure receipts — ${storeId}`)}, icon("file"), "Download receipts")));
  } catch (e) {
    body.replaceChildren(errorState(unavailableReason(e)));
  }
}

// Where a finished run's results live. A saved audit or scan opens in the
// History; a DPIA draft is kept only with its run, so it reopens on New assessment.
function runResultTarget(job) {
  if (String(job?.status) !== "succeeded") return null;
  const result = job.result || {};
  const store = String(job.resource || "").split("/")[0];
  if (job.kind === "audit" && result.id) return ["View audit results", "history", {audit: result.id, store}];
  if ((job.kind === "posture" || job.kind === "scan_integrity") && result.id) {
    return ["View scan results", "history", {scan: result.id, list: "scans"}];
  }
  if (job.kind === "pia") return ["Open DPIA draft", "assess", {job: job.id, store, mode: "dpia"}];
  return null;
}

// Background jobs are the same runs the assessment page tracks. A queued or
// running one is still moving, so it keeps the live card the assessment page
// shows; a finished one is a record, so it is a row in one table. An
// interrupted or failed run's reason is printed in its row, not buried in a
// JSON dump the reader has to go looking for.
const LIVE_RUN_STATES = new Set(["queued", "running"]);

function runLabel(job) {
  return `${RUN_KIND_LABEL[job.kind] || humanize(job.kind) || "Run"} — ${job.resource || "no scope recorded"}`;
}

function runRecordButton(job) {
  return () => showJson(`/admin/jobs/${encodeURIComponent(job.id)}`, "Run record");
}

function finishedRunRow(job) {
  const status = String(job.status || "unknown");
  const meta = RUN_STATE[status] || {tone: "unknown", text: status};
  const target = runResultTarget(job);
  const why = status === "failed" ? job.error || "This run failed."
    : status === "interrupted"
      ? job.error || "A restart ended this run before it finished. Its results were not recorded."
      : "";
  const started = job.started_at || job.created_at;
  return h("tr", {class: `run-row run-${status}`},
    h("td", {class: "run-row-name"},
      h("span", {class: "run-row-label"}, runLabel(job)),
      why ? h("span", {class: "sub run-row-error"}, why) : ""),
    h("td", {}, stateChip(meta.tone, meta.text)),
    h("td", {}, started ? formatWhen(started) : h("span", {class: "sub"}, "not started")),
    h("td", {class: "run-elapsed"}, runElapsed(job)),
    h("td", {}, job.actor || h("span", {class: "sub"}, "-")),
    h("td", {}, rowActions(
      target
        ? h("button", {class: "btn small", type: "button", onclick: () => goTo(target[1], target[2])},
            icon("archive"), target[0])
        : "",
      [{label: "Full record", glyph: "code", onclick: runRecordButton(job)}])));
}

async function renderJobs() {
  // Runs is a view within History, so it shares History's layout and switch.
  const box = h("div", {class: "archive-view runs-view"});
  box.append(pageHeader("jobs", "Queued, running, and completed background work."));
  box.append(h("div", {}, historySwitch("runs")));
  const out = h("div", {class: "runs-body"});
  box.append(out);
  out.replaceChildren(loadingState("Loading runs"));
  try {
    const result = await api("/admin/jobs?limit=100");
    const jobs = result.jobs || [];
    if (!jobs.length) {
      out.replaceChildren(panel("Runs", emptyState("No background work has run yet.",
        can("operator") ? {action: () => goTo("assess"), actionLabel: "Run an assessment"} : {})));
      return box;
    }
    const counts = {};
    for (const job of jobs) counts[job.status] = (counts[job.status] || 0) + 1;
    const interrupted = counts.interrupted || 0;
    const live = jobs.filter(job => LIVE_RUN_STATES.has(String(job.status || "queued")));
    const finished = jobs.filter(job => !LIVE_RUN_STATES.has(String(job.status || "queued")));

    out.replaceChildren(
      panel("Standing", h("div", {class: "run-standing"},
        factList(Object.entries(RUN_STATE).map(([key, meta]) =>
          [meta.text, number(counts[key] || 0), key === "interrupted" && counts[key] ? "recorded nothing" : ""]),
          {className: "page-facts", itemClass: "page-fact", valueClass: "page-fact-v", noteClass: "page-fact-n"}),
        interrupted
          ? statusLine(`${plural(interrupted, "run")} ${interrupted === 1 ? "was" : "were"} interrupted by a restart and ` +
                       "recorded nothing. Their scope was never assessed.", "medium")
          : "")),
      ...live.map(job => runCard(job, {
        label: runLabel(job),
        scope: job.resource,
        body: h("div", {class: "bar"},
          h("button", {class: "btn small", type: "button", onclick: runRecordButton(job)},
            icon("code"), "Full record"),
          job.actor ? h("span", {class: "sub"}, `started by ${job.actor}`) : ""),
      })),
      finished.length
        ? panel("Finished runs", dataTable(["Run", "Status", "Started", "Elapsed",
                                       "Started by", {sr: "Actions"}],
                                      {wrapClass: "table-wrap archive-table runs-table", rows: finished.map(finishedRunRow)}).node)
        : "");
  } catch (e) {
    out.replaceChildren(panel("Runs", errorState(unavailableReason(e), () => route())));
  }
  return box;
}

async function renderHistory() {
  // The registry maps a scan's connector URI to the store id people use, and
  // feeds the store filter; without it the page still renders.
  try { await loadCore(); } catch { /* store ids fall back to shortened URIs */ }
  if (param("audit")) return savedAuditView(param("audit"));
  if (param("scan")) return savedScanView(param("scan"));
  return h("div", {class: "archive-view"},
    pageHeader("history", "Saved audits and the individual scans behind them. Open one to see what it covered and found."),
    await scanArchivePanel(param("store")));
}

async function renderAudit() {
  const r = await api("/audit-log");
  const verified = r.verified === true;
  return h("div", {},
    pageHeader("audit", "Actor-attributed changes and operations."),
    // The chain's verification state is the point of a hash-chained log, so it
    // is stated first rather than left in the response for nobody to read.
    panel("Chain integrity", verified
      ? h("div", {},
          statusLine("The hash chain verifies: no entry has been altered or removed " +
                     "since it was written.", "info"),
          h("p", {class: "sub"}, `${number((r.entries || []).length)} entries checked.`))
      : errorState(r.reason || "The audit log chain does not verify.")),
    panel("Entries", table(["When", "Actor", "Action", "Target", "Details"],
      (r.entries || []).slice().reverse().map(e => h("tr", {},
        h("td", {}, formatWhen(e.ts ?? e.timestamp)),
        h("td", {}, e.actor || "-"),
        h("td", {class: "mono"}, e.action),
        // The API calls this `target`; reading `resource` showed "-" for every row.
        h("td", {}, e.target || e.resource || "-"),
        h("td", {}, kvList(e.details || {})))))));
}

const READY_TONE = {ok: "ok", ready: "ok", error: "critical", not_ready: "critical", disabled: "info"};

// Local NLP detection. Degraded means names, places and organisations are
// not being found; the regex detectors still run. Saying how to install the
// model beats saying only that it is missing.
// `unverified`: the model is present but its self-check has not confirmed it
// finds what it should, so its results are not relied on yet. `loading`: it
// is still starting. Neither is green, and neither reads as "off".
const DETECTION_STATE = {
  ready: {tone: "ok", text: "Ready"},
  degraded: {tone: "medium", text: "Degraded"},
  unavailable: {tone: "critical", text: "Unavailable"},
  disabled: {tone: "info", text: "Off"},
  unverified: {tone: "medium", text: "Not yet verified", glyph: "sev-medium"},
  loading: {tone: "info", text: "Loading model", glyph: "clock"},
};
const DETECTION_TONE = Object.fromEntries(Object.entries(DETECTION_STATE).map(([key, meta]) => [key, meta.tone]));

function detectionChip(status) {
  const meta = DETECTION_STATE[status] || {tone: "unknown", text: humanize(status) || "Unknown"};
  return stateChip(meta.tone, meta.text, {glyph: meta.glyph || ""});
}

function installCommand(command) {
  return h("div", {class: "install-line"},
    h("code", {class: "gate-cli-line"}, command),
    h("button", {class: "btn small", type: "button", "aria-label": "Copy install command",
                 onclick: () => copyText(command, "Install command")}, icon("copy"), "Copy"));
}

function detectionPanel(detection) {
  if (detection?.error) {
    return panel("Detection", unavailableState("Detection status could not be read.", detection.error));
  }
  const d = detection || {};
  const status = String(d.status || "unknown");
  const limited = ["degraded", "unavailable", "unverified", "loading"].includes(status);
  const command = typeof d.install_command === "string" ? d.install_command.trim() : "";
  // The reason may already quote the command; it is shown once, as the line
  // that can be copied.
  const reason = command
    ? String(d.reason || "").split(/;\s*/).filter(part => !part.includes(command)).join("; ")
    : String(d.reason || "");
  return panel("Detection", h("div", {},
    h("dl", {class: "kv"},
      h("dt", {}, "NLP"), h("dd", {}, detectionChip(status)),
      d.mode ? [h("dt", {}, "Mode"), h("dd", {}, d.mode)] : "",
      d.requested_model ? [h("dt", {}, "Model"), h("dd", {class: "mono"}, d.active_model || d.requested_model)] : "",
      Array.isArray(d.ner_languages)
        ? [h("dt", {}, "Name languages"), h("dd", {}, d.ner_languages.join(", ") || "none")] : ""),
    limited && reason ? statusLine(sentence(reason), "medium") : "",
    limited && command ? installCommand(command) : ""));
}

async function renderStatus() {
  const [ready, version, detection] = await Promise.all([
    api("/readyz").catch(e => ({status: "not_ready", error: e.message})), api("/version"),
    api("/admin/detection").catch(e => ({error: unavailableReason(e)}))]);
  const onOff = on => stateChip(on ? "ok" : "info", on ? "enabled" : "disabled");
  const checks = Object.entries(ready.checks || {});
  return h("div", {},
    pageHeader("status", "Operational readiness and installed package versions."),
    panel("This deployment", h("dl", {class: "kv"},
      h("dt", {}, "Readiness"), h("dd", {}, stateChip(READY_TONE[ready.status] || "unknown", ready.status || "unknown")),
      h("dt", {}, "VecShield"), h("dd", {class: "mono"}, version.version || "unknown"),
      h("dt", {}, "Detectors"), h("dd", {}, h("span", {class: "mono"}, version.detection_version || "unknown"),
        h("span", {class: "sub"}, " · installed package")),
      // Auth off is worth noticing on a console that can erase data; an
      // admin API that is off is just a configuration.
      h("dt", {}, "Auth"), h("dd", {}, version.auth_enabled ? onOff(true) : stateChip("medium", "disabled")),
      h("dt", {}, "Admin API"), h("dd", {}, onOff(version.admin_enabled)))),
    panel("Readiness checks", h("div", {},
      ready.error ? statusLine(ready.error, "error") : "",
      checks.length
        ? table(["Check", "State"], checks.map(([name, value]) => h("tr", {},
            h("td", {}, prettyKey(name)),
            h("td", {}, stateChip(READY_TONE[value] || "unknown", String(value))))))
        : statusLine("The readiness probe returned no per-check detail.", "unknown"),
      h("details", {class: "evidence-data"}, h("summary", {}, icon("code"), "Raw record"), jsonBlock(ready)))),
    detectionPanel(detection),
    // Each detector by the name the Detectors screen gives it; the id it is
    // configured by is one hover away.
    panel("Runtime detectors", Array.isArray(version.detectors) && version.detectors.length
      ? h("div", {class: "tag-row"}, version.detectors.map(d => {
          const known = DETECTOR_UI.find(x => x.key === d);
          return h("span", {class: "tag", title: known ? d : null}, known ? known.name : d);
        }))
      : statusLine(Array.isArray(version.detectors) ? "No runtime detector is installed."
                                                    : "This server did not report its runtime detectors.", "unknown")));
}

// ------------------------------------------------------------------ users ---
// Who can sign in, and with which roles. Only an admin on a deployment with
// sign-in on is offered this screen; the server refuses everyone else anyway.

function userStatus(u) {
  if (u.disabled) return stateChip("unknown", "disabled", {glyph: "sev-notrun"});
  if (u.must_change_password) return stateChip("medium", "must change password");
  return stateChip("ok", "active");
}

function roleChips(roles) {
  const list = sortedRoles(roles);
  return list.length
    ? h("div", {class: "tag-row role-chips"}, list.map(r => h("span", {class: `tag role-${r}`}, r)))
    : h("span", {class: "sub"}, "no roles");
}

function lastSignIn(value) {
  if (!value) return h("span", {class: "sub"}, "never");
  const millis = toMillis(value);
  return Number.isFinite(millis)
    ? h("time", {datetime: new Date(millis).toISOString(), title: localTime(value)}, relativeTime(value))
    : h("span", {class: "mono"}, String(value));
}

// One checkbox per role. Admin already includes the others, so ticking it
// says so rather than silently ticking them.
function roleChecks(selected = [], {name = "roles"} = {}) {
  const chosen = new Set(selected);
  const boxes = ROLE_ORDER.slice().reverse().map(role => {
    const box = h("input", {type: "checkbox", name, value: role, checked: chosen.has(role)});
    return {role, box, row: h("label", {class: "check-row role-check"}, box,
      h("span", {}, h("span", {class: "strong"}, role), h("span", {class: "sub"}, ` ${ROLE_HINT[role]}`)))};
  });
  const node = h("fieldset", {class: "role-checks"}, h("legend", {}, "Roles"), boxes.map(b => b.row));
  return {node, value: () => boxes.filter(b => b.box.checked).map(b => b.role),
          focus: () => boxes[0]?.box.focus?.()};
}

function passwordRule() {
  return `At least ${state.auth.password_policy?.min_length || 12} characters.`;
}

async function renderUsers() {
  const box = h("div", {class: "users-view"});
  if (!viewAvailable("users")) {
    box.append(pageHeader("users"),
      panel("Users", unavailableState(
        state.auth.login_enabled ? "Only an admin can manage users." : "Sign-in is off on this server.",
        state.auth.login_enabled
          ? "Ask an admin to change your roles if you need this."
          : "Accounts are managed here once the server enables sign-in; until then access is by token.")));
    return box;
  }

  const notice = h("div", {class: "users-notice"});
  const addSlot = h("div", {});
  const listSlot = h("div", {}, loadingState("Reading users"));
  const addButton = h("button", {class: "btn primary", type: "button", "aria-expanded": "false",
                                 "aria-controls": "add-user-panel", onclick: () => toggleAdd()},
    icon("plus"), "Add user");
  box.append(pageHeader("users", "Who can sign in, and what each person may do.", addButton),
             notice, addSlot, panel("Accounts", listSlot));

  let users = [];
  let editing = null;   // {username, kind: "roles" | "password"}

  function say(message, tone = "ok") {
    notice.replaceChildren(message ? statusLine(message, tone, {live: true}) : "");
  }

  async function load() {
    try {
      const data = await api("/auth/users");
      users = Array.isArray(data?.users) ? data.users : [];
      draw();
    } catch (e) {
      listSlot.replaceChildren(errorState(unavailableReason(e), () => { listSlot.replaceChildren(loadingState("Reading users")); load(); }));
    }
  }

  // After a change to one's own account the session's roles may have moved.
  async function refreshSelf(username) {
    if (username !== state.auth.user?.username) return;
    await loadSession();
    buildNav();
    const actions = document.getElementById("top-actions");
    const old = actions?.querySelector?.(".menu-wrap");
    if (old && state.auth.login_enabled) old.replaceWith(accountMenu());
    if (!viewAvailable("users")) route();
  }

  function toggleAdd(open = !addSlot.children.length) {
    addButton.setAttribute("aria-expanded", String(open));
    if (!open) { addSlot.replaceChildren(); addButton.focus?.(); return; }
    const username = textInput("", {autocomplete: "off", autocapitalize: "none", spellcheck: "false", required: true});
    const password = textInput("", {type: "password", autocomplete: "new-password", required: true,
                                    "aria-describedby": "new-user-rule"});
    const roles = roleChecks(["viewer"]);
    const error = authError();
    const form = h("form", {class: "user-form", novalidate: true, onsubmit: async event => {
      event?.preventDefault?.();
      const name = username.value.trim();
      const min = state.auth.password_policy?.min_length || 12;
      const problem = !name ? [username, "Enter a username."]
        : password.value.length < min ? [password, `Use a temporary password of at least ${min} characters.`]
        : !roles.value().length ? [null, "Choose at least one role."] : null;
      if (problem) {
        setAuthError(error, problem[1], problem[0]);
        (problem[0] || roles).focus?.();
        return;
      }
      try {
        await api("/auth/users", {method: "POST",
          body: JSON.stringify({username: name, password: password.value, roles: roles.value()})});
        toggleAdd(false);
        say(`${name} was added. They choose their own password at first sign-in.`);
        await load();
      } catch (e) {
        setAuthError(error, sentence(e.message), username);
      }
    }},
      h("div", {class: "user-form-grid"},
        field("Username", username),
        h("label", {class: "field"}, h("span", {}, "Temporary password"), password,
          h("small", {class: "auth-hint", id: "new-user-rule"}, passwordRule()))),
      roles.node,
      statusLine("They will choose their own password the first time they sign in.", "info"),
      error,
      h("div", {class: "bar user-form-actions"},
        h("button", {class: "btn primary", type: "submit"}, "Create user"),
        h("button", {class: "btn", type: "button", onclick: () => toggleAdd(false)}, "Cancel")));
    addSlot.replaceChildren(panel("Add user", form, null,
                                  {className: "user-add", id: "add-user-panel", headingId: "add-user-title"}));
    username.focus?.();
  }

  function editRow(u) {
    const cells = 6;
    const error = authError();
    const close = () => { editing = null; draw(); };
    let body;
    if (editing.kind === "roles") {
      const roles = roleChecks(u.roles || []);
      body = h("form", {class: "user-form", novalidate: true, onsubmit: async event => {
        event?.preventDefault?.();
        if (!roles.value().length) { setAuthError(error, "Choose at least one role."); return; }
        try {
          await api(`/auth/users/${encodeURIComponent(u.username)}`, {method: "PATCH",
            body: JSON.stringify({roles: roles.value()})});
          editing = null;
          say(`Roles for ${u.username} saved.`);
          await load();
          await refreshSelf(u.username);
        } catch (e) {
          setAuthError(error, sentence(e.message));
        }
      }},
        roles.node, error,
        h("div", {class: "bar user-form-actions"},
          h("button", {class: "btn primary small", type: "submit"}, "Save roles"),
          h("button", {class: "btn small", type: "button", onclick: close}, "Cancel")));
      setTimeout(() => roles.focus(), 0);
    } else {
      const password = textInput("", {type: "password", autocomplete: "new-password", required: true,
                                      "aria-describedby": `reset-rule-${u.username}`});
      body = h("form", {class: "user-form", novalidate: true, onsubmit: async event => {
        event?.preventDefault?.();
        const min = state.auth.password_policy?.min_length || 12;
        if (password.value.length < min) {
          setAuthError(error, `Use a temporary password of at least ${min} characters.`, password);
          password.focus?.();
          return;
        }
        try {
          await api(`/auth/users/${encodeURIComponent(u.username)}/password`, {method: "POST",
            body: JSON.stringify({new_password: password.value})});
          editing = null;
          say(`Password for ${u.username} reset. They choose a new one at next sign-in.`);
          await load();
        } catch (e) {
          setAuthError(error, sentence(e.message), password);
        }
      }},
        h("div", {class: "user-form-grid"},
          h("label", {class: "field"}, h("span", {}, "Temporary password"), password,
            h("small", {class: "auth-hint", id: `reset-rule-${u.username}`},
              `${passwordRule()} They choose a new one at next sign-in.`))),
        error,
        h("div", {class: "bar user-form-actions"},
          h("button", {class: "btn primary small", type: "submit"}, "Reset password"),
          h("button", {class: "btn small", type: "button", onclick: close}, "Cancel")));
      setTimeout(() => password.focus?.(), 0);
    }
    const title = editing.kind === "roles" ? `Edit roles for ${u.username}` : `Reset password for ${u.username}`;
    return h("tr", {class: "user-edit-row"}, h("td", {colspan: cells},
      h("div", {class: "user-edit", role: "group", "aria-label": title},
        h("h3", {class: "user-edit-title"}, title), body)));
  }

  async function setDisabled(u, disabled) {
    const self = u.username === state.auth.user?.username;
    const ok = await confirmAction(disabled
      ? {title: `Disable ${u.username}?`,
         message: `${u.username} is signed out and cannot sign in until an admin enables the account again. Their audit history is kept.`,
         confirmLabel: "Disable", danger: true}
      : {title: `Enable ${u.username}?`, message: `${u.username} can sign in again with their current password.`,
         confirmLabel: "Enable"});
    if (!ok) return;
    try {
      await api(`/auth/users/${encodeURIComponent(u.username)}`, {method: "PATCH", body: JSON.stringify({disabled})});
      say(`${u.username} ${disabled ? "disabled" : "enabled"}.`);
      await load();
      if (self) await refreshSelf(u.username);
    } catch (e) {
      say(sentence(e.message), "error");
    }
  }

  function draw() {
    const me = state.auth.user?.username;
    const rows = [];
    for (const u of users) {
      const open = editing && editing.username === u.username;
      rows.push(h("tr", {class: open ? "row-open" : ""},
        h("td", {}, h("span", {class: "strong mono"}, u.username),
          u.username === me ? h("span", {class: "sub"}, " (you)") : ""),
        h("td", {}, roleChips(u.roles)),
        h("td", {}, userStatus(u)),
        h("td", {}, lastSignIn(u.last_login_at)),
        h("td", {}, u.created_by
          ? h("span", {title: u.created_at ? localTime(u.created_at) : null}, u.created_by)
          : h("span", {class: "sub"}, "-")),
        h("td", {}, rowActions(
          h("button", {class: "btn small", type: "button", "aria-expanded": String(Boolean(open && editing.kind === "roles")),
                       onclick: () => { editing = {username: u.username, kind: "roles"}; draw(); }},
            icon("edit"), "Edit roles"),
          [
            {label: "Reset password", glyph: "key",
             onclick: () => { editing = {username: u.username, kind: "password"}; draw(); }},
            u.disabled
              ? {label: "Enable", glyph: "check", onclick: () => setDisabled(u, false)}
              : {label: "Disable", glyph: "close", danger: true, onclick: () => setDisabled(u, true)},
          ]))));
      if (open) rows.push(editRow(u));
    }
    const list = users.length ? table(["Username", "Roles", "Status", "Last sign-in", "Created by", ""], rows) : null;
    // The edit row spans every column; on a phone it must not borrow the
    // first column's label.
    for (const row of rows) {
      if (row.classList.contains("user-edit-row")) row.firstChild?.removeAttribute?.("data-label");
    }
    const counts = {
      active: users.filter(u => !u.disabled).length,
      disabled: users.filter(u => u.disabled).length,
      pending: users.filter(u => !u.disabled && u.must_change_password).length,
    };
    listSlot.replaceChildren(
      users.length
        ? h("p", {class: "sub users-count"},
            `${plural(counts.active, "active account")}`,
            counts.pending ? ` · ${number(counts.pending)} yet to choose a password` : "",
            counts.disabled ? ` · ${number(counts.disabled)} disabled` : "")
        : "",
      list || emptyState("No accounts are recorded."));
  }

  await load();
  return box;
}

async function showJson(path, title) {
  try { modal(title, jsonBlock(await api(path)), null, "Close"); } catch (e) { toast(e.message, "err"); }
}

// Tags that take focus without being given a tabindex. Walking the tree beats a
// selector string here: it behaves identically in the browser and in the test
// harness, so the trap is actually testable.
const FOCUSABLE_TAGS = new Set(["A", "BUTTON", "INPUT", "SELECT", "TEXTAREA", "SUMMARY"]);

function focusableWithin(node, found = []) {
  for (const child of node.children || []) {
    const tabindex = child.getAttribute?.("tabindex");
    const explicit = tabindex != null;
    const takesFocus = explicit
      ? tabindex !== "-1"
      : FOCUSABLE_TAGS.has(child.tagName) && !child.disabled && !child.hidden;
    if (takesFocus) found.push(child);
    focusableWithin(child, found);
  }
  return found;
}

// Dialogs form a stack. An ordinary dialog replaces whatever is open; a detail
// opened from inside another detail (a chunk from a finding, a case from a
// finding, a finding from a list dialog) is pushed on top, hides the one
// beneath, and offers Back to it, so the reader never loses where they were.
// `openDialog` is always the top of the stack, or null.
const dialogStack = [];
let openDialog = null;

function syncOpenDialog() {
  openDialog = dialogStack[dialogStack.length - 1] || null;
  syncScrollLock();
}

// `actions` replaces a read-only dialog's lone Close button with the actions
// that matter there (the X still closes). `drawer` docks it to the right edge,
// full height, as a detail panel beside the list it came from.
function modal(title, body, onSubmit, submitLabel = "Save", {stack = false, actions = null, drawer = false, meta = ""} = {}) {
  const returnFocus = document.activeElement || null;
  const parent = stack ? dialogStack[dialogStack.length - 1] : null;
  if (!parent) closeAllDialogs({restoreFocus: false});
  const depth = dialogStack.length + 1;
  const headingId = depth === 1 ? "modal-title" : `modal-title-${depth}`;
  const cancel = h("button", {class: "btn", type: "button", onclick: closeModal}, "Cancel");
  const submit = h("button", {class: "btn primary", type: onSubmit ? "submit" : "button"},
    submitLabel);
  if (!onSubmit) submit.addEventListener("click", closeModal);

  // A real <form> gives Enter-to-submit, native validation, and the browser's
  // own required-field handling — none of which a bare button can provide.
  const inner = onSubmit
    ? h("form", {class: "modal-form", onsubmit: async event => {
        event?.preventDefault?.();
        try { await onSubmit(); } catch (e) { toast(e.message, "err"); }
      }},
      h("div", {class: "modal-body"}, body),
      h("div", {class: "modal-foot"}, cancel, submit))
    : h("div", {class: "modal-inner"},
      h("div", {class: "modal-body"}, body),
      h("div", {class: "modal-foot"}, actions && actions.length ? actions : submit));

  // Back names where it goes: "Back" alone does not say what comes back.
  const back = parent
    ? h("button", {class: "btn small modal-back", type: "button", onclick: closeModal,
                   "aria-label": `Back to ${parent.title}`},
        h("span", {"aria-hidden": "true"}, "←"), "Back")
    : "";

  const dialog = h("div", {
    class: `modal${drawer ? " modal-drawer" : ""}`, role: "dialog", "aria-modal": "true", "aria-labelledby": headingId,
  },
    h("div", {class: "modal-head"},
      h("div", {class: "modal-head-main"}, back,
        h("div", {class: "modal-titles"}, h("h2", {id: headingId}, title),
          meta ? h("div", {class: "sub mono modal-meta"}, meta) : "")),
      h("button", {class: "icon-btn", type: "button", onclick: closeModal, "aria-label": "Close"}, icon("close"))),
    inner);

  const backdrop = h("div", {
    class: `modal-backdrop${parent ? " modal-stacked" : ""}${drawer ? " drawer-backdrop" : ""}`,
    id: depth === 1 ? "modal-backdrop" : `modal-backdrop-${depth}`,
    onkeydown: event => dialogKeydown(event, dialog),
    onmousedown: event => { if (event?.target === backdrop) closeModal(); },
  }, dialog);

  // The one beneath stays mounted, state and scroll intact, but out of the way.
  if (parent) parent.backdrop.hidden = true;
  dialogStack.push({backdrop, dialog, returnFocus, title: String(title || "")});
  syncOpenDialog();
  document.body.append(backdrop);
  focusableWithin(dialog)[0]?.focus?.();
  return backdrop;
}

function dialogKeydown(event, dialog) {
  if (event?.key === "Escape") {
    event.preventDefault?.();
    event.stopPropagation?.();
    closeModal();
    return;
  }
  if (event?.key !== "Tab") return;
  const items = focusableWithin(dialog);
  if (items.length < 2) return;
  const first = items[0];
  const last = items[items.length - 1];
  const active = document.activeElement;
  if (event.shiftKey && active === first) {
    event.preventDefault?.();
    last.focus?.();
  } else if (!event.shiftKey && active === last) {
    event.preventDefault?.();
    first.focus?.();
  }
}

// Closes the top dialog. If another was beneath it, that one comes back as it
// was left, and focus returns to the control inside it that opened this one.
function closeModal() {
  const open = dialogStack.pop() || null;
  syncOpenDialog();
  if (open) open.backdrop.remove();
  else document.getElementById("modal-backdrop")?.remove();
  if (open?.onClose) open.onClose();
  if (openDialog) openDialog.backdrop.hidden = false;
  // Returning focus to whatever opened the dialog is what keeps keyboard and
  // screen-reader users from being dropped at the top of the document.
  open?.returnFocus?.focus?.();
}

// Every open dialog, top first. Navigation calls this: a dialog belongs to the
// page it was opened on and must not float over the next one.
function closeAllDialogs({restoreFocus = true} = {}) {
  let bottom = null;
  while (dialogStack.length) {
    const open = dialogStack.pop();
    open.backdrop.remove();
    if (open.onClose) open.onClose();
    bottom = open;
  }
  syncOpenDialog();
  if (restoreFocus) bottom?.returnFocus?.focus?.();
}

// The one way the console asks before doing something that matters. It is an
// in-page dialog, never window.confirm: that can be unavailable (it returned
// undefined and an erasure went ahead unasked) or suppressed by the browser.
// It resolves true only when someone pressed the confirm button; if it cannot
// be shown, it says so and resolves false, so the action never falls through.
// Irreversible actions pass `typed`: the button stays disabled until that
// exact text (a store id, a subject) has been typed.
function confirmAction({title, message, confirmLabel = "Confirm", danger = false,
                        typed = "", typedLabel = "", details = null} = {}) {
  return new Promise(resolve => {
    let settled = false;
    const expected = String(typed || "");
    const returnFocus = document.activeElement || null;
    const depth = dialogStack.length + 1;
    const headingId = `confirm-title-${depth}`;
    const messageId = `confirm-message-${depth}`;
    const input = expected
      ? textInput("", {autocomplete: "off", spellcheck: "false",
                       "aria-label": typedLabel || `Type ${expected} to confirm`})
      : null;
    const ok = h("button", {class: `btn ${danger ? "danger-solid" : "primary"}`, type: "submit",
                            disabled: Boolean(expected)}, confirmLabel);
    const cancel = h("button", {class: "btn", type: "button", onclick: () => finish(false)}, "Cancel");
    const matches = () => !expected || (input && input.value.trim() === expected);
    input?.addEventListener("input", () => { ok.disabled = !matches(); });

    const form = h("form", {class: "modal-form", onsubmit: event => {
      event?.preventDefault?.();
      // Checked again here: a disabled button is a hint, not a guarantee.
      if (!matches()) { input?.focus?.(); return; }
      finish(true);
    }},
      h("div", {class: "modal-body confirm-body"},
        h("p", {id: messageId, class: "confirm-message"}, message),
        details || "",
        input
          ? h("label", {class: "field confirm-typed"},
              h("span", {}, typedLabel || "To confirm, type ", h("code", {}, expected)),
              input)
          : ""),
      h("div", {class: "modal-foot"}, cancel, ok));

    const dialog = h("div", {class: "modal modal-confirm", role: "alertdialog", "aria-modal": "true",
                             "aria-labelledby": headingId, "aria-describedby": messageId},
      h("div", {class: "modal-head"}, h("h2", {id: headingId}, title),
        h("button", {class: "icon-btn", type: "button", "aria-label": "Cancel",
                     onclick: () => finish(false)}, icon("close"))),
      form);
    const backdrop = h("div", {class: "modal-backdrop modal-stacked", id: `confirm-backdrop-${depth}`,
      onkeydown: event => dialogKeydown(event, dialog),
      onmousedown: event => { if (event?.target === backdrop) finish(false); }}, dialog);
    const entry = {backdrop, dialog, returnFocus, title: String(title || ""),
                   onClose: () => finish(false)};

    function finish(value) {
      if (settled) return;
      settled = true;
      const index = dialogStack.indexOf(entry);
      if (index !== -1) {
        dialogStack.splice(index, 1);
        syncOpenDialog();
        backdrop.remove();
        returnFocus?.focus?.();
      }
      resolve(value === true);
    }

    try {
      dialogStack.push(entry);
      syncOpenDialog();
      document.body.append(backdrop);
      if (backdrop.isConnected !== true || backdrop.hidden) throw new Error("not mounted");
    } catch {
      // Refuse rather than proceed: an action that needed a confirmation must
      // not happen because the question could not be asked.
      const index = dialogStack.indexOf(entry);
      if (index !== -1) dialogStack.splice(index, 1);
      syncOpenDialog();
      try { backdrop.remove(); } catch { /* it was never mounted */ }
      settled = true;
      toast("The confirmation could not be shown, so nothing was done.", "err");
      resolve(false);
      return;
    }
    (input || cancel).focus?.();
  });
}

// ================================================================ drill-down ===
// From an observation to the text behind it, and to the rule that says it
// matters. A finding stores offsets and a masked preview; the chunk itself is
// fetched from the store on request (see reveal.py) and never kept here.

// The registry id for a finding's store. Findings carry the store *name* the
// connector reports (a path, for a local store); the API wants the id it was
// registered under. Exact match first, then the name ending in the id.
function storeIdFor(name) {
  const stores = state.stores || [];
  const text = String(name || "");
  const exact = stores.find(s => s.store_id === text);
  if (exact) return exact.store_id;
  const suffix = stores.find(s => text.endsWith(`/${s.store_id}`) || text.endsWith(s.store_id));
  return suffix ? suffix.store_id : text;
}

// A store as a reader knows it. Findings carry the name the connector
// reports, which for a local store is a file:// path four lines long; the
// registered id is what people call it. An unregistered URI is shortened to
// its last two segments. The full value stays in the title.
function storeLabel(name) {
  const text = String(name || "");
  if (!text) return "-";
  const id = storeIdFor(text);
  if (id !== text) return id;
  const uri = text.match(/^[a-z][a-z0-9+.-]*:\/\/(.*)$/i);
  if (!uri) return text;
  const parts = uri[1].split(/[/?#]/).filter(Boolean);
  return parts.length > 2 ? `\u2026/${parts.slice(-2).join("/")}` : (parts.join("/") || text);
}

function findingLocation(f) {
  const full = [f.store, f.collection].filter(Boolean).join(" / ");
  return h("div", {class: "location", title: full || null},
    h("div", {class: "mono"}, storeLabel(f.store)),
    h("div", {class: "sub"}, f.collection || "store scope"));
}

// Chunk ids a finding's examples name. Isolation probes record the chunk that
// leaked rather than the one that was scanned; both are chunks a reader can open.
function chunkRefs(finding) {
  const examples = ((finding.evidence || {}).examples) || [];
  const refs = [];
  for (const example of examples) {
    if (!example || typeof example !== "object") continue;
    if (example.chunk_id) {
      refs.push({chunkId: String(example.chunk_id), label: example.label || "",
                 detectors: example.detectors || [], spans: example.spans || [],
                 explanations: example.explanations || [], role: "scanned"});
    }
    if (example.leaked_id) {
      refs.push({chunkId: String(example.leaked_id), label: "cross-tenant",
                 detectors: ["isolation probe"], spans: [], explanations: [],
                 role: `leaked to ${example.probe_tenant || "another tenant"} from ${example.leaked_tenant || "?"}`});
    }
  }
  return refs;
}

// ---------------------------------------------------------- obligations ---
// finding → policy that fires on it → template it came from → citation →
// criteria of that framework informed by the finding's check. The last hop is
// a join by check name and is labelled as one.

function policyAppliesToStore(policy, finding) {
  if (!policy.scope_store) return true;
  const id = storeIdFor(finding.store);
  return policy.scope_store === id || policy.scope_store === finding.store;
}

function obligationTrace(finding, {policies = [], templates = [], pack = null} = {}) {
  const firing = (policies || []).filter(p =>
    policyAppliesToStore(p, finding) &&
    (!p.scope_collection || p.scope_collection === finding.collection) &&
    findingMatchesRule(finding, p.when || {}));
  const templateIds = new Set(firing.map(p => p.template_id).filter(Boolean));
  const fromTemplates = (templates || []).filter(t => templateIds.has(t.id));
  // Templates that would match even where no policy has been created from
  // them: the rule exists, nobody has switched it on for this store.
  const dormant = (templates || []).filter(t =>
    !templateIds.has(t.id) && findingMatchesRule(finding, t.when || {}));
  const frameworks = new Set(fromTemplates.map(t => t.regulation).filter(Boolean));
  const check = String((finding.evidence || {}).check || finding.category || "");
  const criteria = (pack?.criteria || []).filter(c =>
    frameworks.has(c.framework) && (c.technical_checks || []).includes(check));
  return {policies: firing, templates: fromTemplates, dormant, criteria,
          check, frameworks: [...frameworks]};
}

async function obligationView(finding) {
  await loadCore();
  let pack = null;
  try { pack = await loadPack(); } catch { pack = null; }
  const trace = obligationTrace(finding, {policies: state.policies, templates: state.templates, pack});
  const box = h("div", {class: "trace"});

  box.append(h("div", {class: "trace-step"},
    h("div", {class: "trace-k"}, icon("sliders"), "Policies that fire on this finding"),
    trace.policies.length
      ? h("ul", {class: "trace-list"}, trace.policies.map(p => h("li", {},
          h("button", {class: "link", type: "button",
                       onclick: () => goTo("policies", {q: p.name})},
            h("span", {class: "strong"}, p.name)),
          h("div", {class: "sub"}, `${ruleSummary(p.when || {})} · scope ${scopeText(p)} · ` +
            `action ${p.action || "-"}`, p.enabled === false ? " · disabled" : ""))))
      : h("p", {class: "sub"}, state.policiesError
          ? `Policies could not be read: ${state.policiesError}`
          : "No configured policy matches this finding. It is an observation without a rule behind it.")));

  box.append(h("div", {class: "trace-step"},
    h("div", {class: "trace-k"}, icon("layers"), "Rule and citation"),
    trace.templates.length
      ? h("ul", {class: "trace-list"}, trace.templates.map(t => h("li", {},
          h("button", {class: "link", type: "button",
                       onclick: () => goTo("templates", {q: t.id})},
            h("span", {class: "strong"}, t.name)),
          h("div", {class: "sub"}, `${t.regulation || "General"} · ${attributionLine(t)}`),
          h("div", {class: "tag-row"},
            ((t.attribution || {}).sources || []).map(src => sourceTag(src))),
          applicabilityNote(t))))
      : h("p", {class: "sub"}, "The matching policies are custom rules with no framework citation."),
    trace.dormant.length
      ? h("details", {class: "evidence-data"},
          h("summary", {}, icon("info"),
            `${plural(trace.dormant.length, "template")} would match but no policy uses them here`),
          h("ul", {class: "trace-list"}, trace.dormant.map(t => h("li", {},
            h("span", {class: "strong"}, t.name), " ",
            h("span", {class: "sub"}, `${t.regulation || "General"} · not enabled for this store`)))))
      : ""));

  box.append(h("div", {class: "trace-step"},
    h("div", {class: "trace-k"}, icon("check"), "Criteria this observation informs"),
    trace.criteria.length
      ? h("ul", {class: "trace-list"}, trace.criteria.map(c => h("li", {},
          h("button", {class: "link", type: "button",
                       onclick: () => goTo("criteria", {framework: c.framework,
                                                        store: storeIdFor(finding.store)})},
            h("span", {class: "mono strong"}, c.criterion_id)),
          h("div", {class: "sub"}, c.paraphrase),
          h("div", {class: "sub"}, `${c.framework} · ` +
            `${plural((c.applicability_questions || []).length, "applicability question")} to answer`))))
      : h("p", {class: "sub"}, trace.frameworks.length
          ? `No ${trace.frameworks.join("/")} criterion names the ${trace.check || "?"} check.`
          : "No framework is in the trace, so no criterion is."),
    h("p", {class: "sub trace-caveat"},
      "Criteria are joined by framework and check name; a match here is an observation " +
      "a criterion can use, not a conclusion about it.")));
  return box;
}

// ----------------------------------------------------------- chunk view ---

const chunkCache = new Map();  // masked views only, for this session

async function fetchChunkView({store, collection, chunkId, findingId = "", level = "masked", reason = ""}) {
  const params = new URLSearchParams({reveal: level});
  if (findingId) params.set("finding_id", findingId);
  if (reason) params.set("reason", reason);
  const path = `/stores/${encodeURIComponent(store)}/collections/${encodeURIComponent(collection)}` +
               `/chunks/${encodeURIComponent(chunkId)}?${params}`;
  return api(path);
}

function spanTone(label) {
  return {secret: "critical", pan: "critical", phi: "high", pii: "medium",
          injection: "high", none: "info"}[String(label || "").toLowerCase()] || "medium";
}

// The text with its matches marked. Text nodes and <mark>s, never HTML.
function markedSurface(surface, {onSpan, hot}) {
  const text = surface.text || "";
  const spans = [...(surface.spans || [])].sort((a, b) => a.start - b.start || a.end - b.end);
  const out = h("pre", {class: "chunk-text"});
  let cursor = 0;
  let index = 0;
  const seen = new Set();
  for (const span of spans) {
    const key = `${span.start}:${span.end}`;
    if (span.start < cursor || seen.has(key)) { index += 1; continue; }
    seen.add(key);
    out.append(document.createTextNode(text.slice(cursor, span.start)));
    const siblings = spans.filter(s => s.start === span.start && s.end === span.end);
    const detectors = [...new Set(siblings.map(s => s.detector))].join(", ");
    const mark = h("mark", {
      class: `span sev-${spanTone(span.label)}${span.disputed ? " span-disputed" : ""}${hot === index ? " span-hot" : ""}`,
      tabindex: "0", role: "button", dataset: {span: String(index)},
      title: `${span.label || "match"} · ${detectors} · ${span.confidence || "uncertain"}`,
      onclick: () => onSpan(index),
      onkeydown: e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault?.(); onSpan(index); } },
    },
      document.createTextNode(text.slice(span.start, span.end)),
      h("span", {class: "span-tag", "aria-hidden": "true"},
        `${span.label || "match"} · ${detectors}${span.disputed ? " ⚠" : ""}`));
    out.append(mark);
    cursor = span.end;
    index += 1;
  }
  out.append(document.createTextNode(text.slice(cursor)));
  return out;
}

function spanExplanation(span, index, {hot, onSpan}) {
  const against = span.counter_signals || [];
  return h("div", {
    class: `explanation${against.length ? " explanation-disputed" : ""}${hot === index ? " explanation-hot" : ""}`,
    id: `span-why-${index}`,
  },
    h("div", {class: "spread"},
      h("button", {class: "link", type: "button", onclick: () => onSpan(index)},
        h("span", {class: "mono strong"}, span.detector || "unknown"),
        h("span", {class: "sub"}, ` · ${span.label || "match"} · ${span.preview || ""}`)),
      stateChip(span.confidence === "likely" ? "ok" : span.confidence === "possible" ? "medium" : "unknown",
                span.confidence || "uncertain")),
    h("p", {class: "sub"}, span.confidence_reason || ""),
    against.length
      ? h("div", {},
          h("div", {class: "metric-k"}, "What argues against this"),
          h("ul", {class: "limitations"}, against.map(c => h("li", {}, c.detail || c.code))))
      : h("p", {class: "sub"}, "Nothing recorded argues against this match."));
}

// The drawer. `finding` is optional: with it the drawer compares live spans to
// the recorded ones and traces the obligation; without it (schema samples) it
// shows the chunk and whatever the classifier finds now.
async function openChunk({store, collection, chunkId, finding = null, spanIndex = null}) {
  const storeId = storeIdFor(store);
  const findingId = finding ? finding.id : "";
  const body = h("div", {class: "chunk-drawer"});
  let view = null;
  let level = "masked";
  let remaskTimer = null;
  let hot = spanIndex;
  const title = `Chunk ${chunkId}`;

  async function load(next = "masked", reason = "") {
    body.replaceChildren(loadingState(next === "raw" ? "Revealing values" : "Fetching the chunk from the store"));
    try {
      view = await fetchChunkView({store: storeId, collection, chunkId, findingId, level: next, reason});
      level = next;
      draw();
    } catch (e) {
      body.replaceChildren(
        e.status === 404
          ? unavailableState(unavailableReason(e), "The finding still records what was seen at the time.")
          : e.status === 409
            ? unavailableState(unavailableReason(e), "The store cannot be read back for this chunk.")
            : errorState(unavailableReason(e), () => load(next, reason)));
    }
  }

  function onSpan(index) {
    hot = hot === index ? null : index;
    draw();
    document.getElementById(`span-why-${index}`)?.scrollIntoView?.({block: "nearest"});
  }

  function revealControls() {
    const reason = textInput("", {placeholder: "Why you need the values (recorded)"});
    reason.setAttribute("aria-label", "Reason for revealing values");
    if (level === "raw") {
      return h("div", {class: "reveal-bar reveal-on", role: "status"},
        icon("eye"),
        h("span", {}, h("strong", {}, "Values shown."), " This view was recorded in the audit log and re-masks in 60 s."),
        h("button", {class: "btn small", type: "button", onclick: () => load("masked")}, "Mask again"));
    }
    return h("div", {class: "reveal-bar"},
      icon("key"),
      h("span", {class: "sub"}, "Values are masked. Revealing them is a processing activity: it needs a reason and is logged with your name."),
      reason,
      h("button", {class: "btn small", type: "button", onclick: () => {
        if (!reason.value.trim()) { toast("A reason is required to reveal values.", "err"); reason.focus?.(); return null; }
        return load("raw", reason.value.trim());
      }}, icon("eye"), "Reveal values"));
  }

  function draw() {
    if (remaskTimer) { clearTimeout(remaskTimer); remaskTimer = null; }
    if (level === "raw") remaskTimer = setTimeout(() => { if (openDialog && level === "raw") load("masked"); }, 60000);
    const allSpans = (view.surfaces || []).flatMap(s => s.spans || []);
    let offset = 0;
    // Metadata surfaces with no match are shown once, in the metadata list
    // below, not as an empty block each.
    const surfaces = (view.surfaces || []).filter(s => s.name === "text" || (s.spans || []).length).map(surface => {
      const base = offset;
      const withIndex = (surface.spans || []).map((s, i) => ({...s, _i: base + i}));
      offset += withIndex.length;
      return {...surface, spans: withIndex};
    });
    const onSpanGlobal = onSpan;

    body.replaceChildren(
      h("div", {class: "chunk-head"},
        h("div", {},
          h("div", {class: "mono strong"}, `${storeId} / ${collection} / ${chunkId}`),
          h("div", {class: "sub", title: String(view.fetched_at || "")},
            `Fetched ${view.fetched_at ? localTime(view.fetched_at) : "just now"} · ` +
            `${plural(view.live_spans, "match", "matches")} now` +
            (finding ? ` · ${number(view.recorded_spans)} recorded by ${finding.id}` : ""))),
        h("div", {class: "tag-row"},
          (view.labels || []).map(l => h("span", {class: `tag sev-${spanTone(l)}`}, l)))),
      view.drift
        ? statusLine("The matches differ from the ones the finding recorded: the chunk or the " +
                     "detectors have changed since that assessment. Highlights show the chunk as it is now.", "medium")
        : view.drift === false
          ? statusLine("The matches are the ones the finding recorded.", "info")
          : "",
      revealControls(),
      h("div", {class: "chunk-cols"},
        h("div", {class: "chunk-main"},
          surfaces.length
            ? surfaces.map(surface => h("section", {class: "surface"},
                h("div", {class: "metric-k"}, surface.name),
                markedSurface({...surface, spans: surface.spans.map(s => ({...s}))},
                              {hot: hot == null ? null : hot - (surface.spans[0]?._i ?? 0),
                               onSpan: i => onSpanGlobal(i + (surface.spans[0]?._i ?? 0))})))
            : emptyState("This chunk has no text surfaces to show."),
          Object.keys(view.metadata || {}).length
            ? h("details", {class: "evidence-data", open: true},
                h("summary", {}, icon("list"), "Metadata"),
                h("dl", {class: "kv"}, Object.entries(view.metadata).flatMap(([k, v]) =>
                  [h("dt", {}, k), h("dd", {class: "mono"}, String(v ?? "-"))])))
            : ""),
        h("aside", {class: "chunk-side"},
          h("div", {class: "metric-k"}, "Why we captured it"),
          allSpans.length
            ? h("div", {class: "explanations"},
                surfaces.flatMap(s => s.spans).map(s => spanExplanation(s, s._i, {hot, onSpan})))
            : statusLine("The classifier finds nothing in this chunk now.", "unknown"),
          finding
            ? h("div", {},
                h("div", {class: "metric-k"}, "What says we must report it"),
                h("div", {id: "chunk-trace"}, loadingState("Tracing the obligation")))
            : "",
          (view.related_findings || []).length
            ? h("div", {},
                h("div", {class: "metric-k"}, "Findings that reference this chunk"),
                h("ul", {class: "trace-list"}, view.related_findings.map(f => h("li", {},
                  badge(f.severity), " ",
                  h("button", {class: "link", type: "button",
                               onclick: () => goTo("findings", {finding: f.id})}, f.title || f.id)))))
            : "")),
      h("p", {class: "sub"}, view.note || ""));

    if (finding) {
      obligationView(finding).then(node => {
        body.querySelector?.("#chunk-trace")?.replaceChildren(node);
      });
    }
  }

  const backdrop = modal(title, body, null, "Close", {stack: true});
  backdrop?.querySelector?.(".modal")?.classList?.add("modal-wide");
  await load("masked");
  return {body, reload: load};
}

// ------------------------------------------------------- finding detail ---
// Tabs, because a finding answers five different questions: what was seen,
// which chunks, why the detector fired, which obligation it touches, and what
// people decided about it.

// Where a case is on its path, drawn as the path. A case that ended on a claim
// is not on the path at all, and says so rather than looking finished.
function caseLifecycle(stateName) {
  const name = String(stateName || "new");
  const at = CASE_LIFECYCLE.indexOf(name);
  // The same sequence as a plan's progress on Actions: ticked when done, the
  // current step selected, each step's state read out before its name.
  return h("div", {class: "fd-life"},
    h("div", {class: "fd-life-k", "aria-hidden": "true"}, "Case path"),
    stepList(CASE_LIFECYCLE.map(step => caseLabel(step)), at,
             {className: "fd-life-steps", label: "Case path", srPrefix: true}),
    at === -1
      ? statusLine(name === "reopened"
          ? "Reopened: work resumes from triage. The earlier decision stays in the history."
          : `Ended as ${caseLabel(name)}: ${CASE_CLAIM_NOTE[name] || "a claim, not a fix"}. ` +
            "It can be reopened.", name === "reopened" ? "high" : "medium")
      : "");
}

// Previous and next within the page of findings it was opened from, so a
// triage pass does not have to close the panel between rows.
function findingStepper(finding, reload, siblings) {
  const index = (siblings || []).findIndex(f => f.id === finding.id);
  if (index === -1 || siblings.length < 2) return null;
  const go = target => {
    closeModal();
    openFinding(target, reload, {siblings});
  };
  const prev = siblings[index - 1];
  const next = siblings[index + 1];
  return h("div", {class: "fd-stepper"},
    h("button", {class: "btn small", type: "button", disabled: !prev,
                 "aria-label": prev ? `Previous finding: ${prev.title || prev.id}` : "No previous finding",
                 onclick: () => prev && go(prev)}, h("span", {"aria-hidden": "true"}, "‹"), "Previous"),
    h("span", {class: "sub"}, `${number(index + 1)} of ${number(siblings.length)}`),
    h("button", {class: "btn small", type: "button", disabled: !next,
                 "aria-label": next ? `Next finding: ${next.title || next.id}` : "No next finding",
                 onclick: () => next && go(next)}, "Next", h("span", {"aria-hidden": "true"}, "›")));
}

async function openFinding(findingOrId, reload = () => route(), {siblings = null} = {}) {
  let finding = typeof findingOrId === "string" ? null : findingOrId;
  let detail = {case_events: [], same_fingerprint: []};
  const id = typeof findingOrId === "string" ? findingOrId : findingOrId.id;
  try {
    detail = await api(`/admin/findings/${encodeURIComponent(id)}`);
    finding = detail.finding || finding;
  } catch (e) {
    if (!finding) { toast(unavailableReason(e), "err"); return null; }
  }
  if (typeof finding.evidence === "string") finding.evidence = safeJson(finding.evidence);

  const content = h("div", {class: "detail-body"});
  const refs = chunkRefs(finding);
  const tabs = [
    ["summary", "Summary", summaryTab],
    ["chunks", `Chunks (${refs.length})`, chunksTab],
    ["why", "Why", () => explanationView(finding)],
    ["obligations", "Obligations", () => obligationView(finding)],
    ["history", "History", historyTab],
  ];
  let current = "summary";

  // A case changed from this drawer: the page behind it is redrawn, and so is
  // this detail, which would otherwise come back showing the old case.
  async function afterCaseChange() {
    reload();
    try {
      detail = await api(`/admin/findings/${encodeURIComponent(id)}`);
      finding = detail.finding || finding;
      if (typeof finding.evidence === "string") finding.evidence = safeJson(finding.evidence);
    } catch { /* keep what is shown; the page behind it was still redrawn */ }
    await show(current);
  }

  // The four things a triager decides on, before the record behind them:
  // how sure, what argues against it, how much the audit saw, and the case.
  function glance() {
    const confidence = findingConfidence(finding);
    const status = findingsCoverage ? findingsCoverage[storeIdFor(finding.store)] : null;
    const kase = finding.case || {};
    return factList([
      ["Confidence", confidenceCell(finding)],
      ["Counter-signals", confidence.disputed
        ? h("button", {class: "link", type: "button", onclick: () => show("why", {focus: true})},
            `${plural(confidence.disputed, "match", "matches")} disputed · read why`)
        : h("span", {class: "sub"}, confidence.total ? "none recorded" : "n/a")],
      ["Store's latest audit", status
        ? coverageChip(status)
        : h("span", {class: "sub"}, "coverage not known here")],
      ["Case", [caseBadge(kase.state), h("span", {class: "sub"}, kase.owner || "unassigned")]],
    ], {className: "fd-glance", itemClass: "fd-fact"});
  }

  async function summaryTab() {
    // A panel opened from a link can arrive before the list has read coverage.
    if (!findingsCoverage && findingsCoverageReady) findingsCoverage = await findingsCoverageReady;
    const ev = finding.evidence || {};
    return h("div", {},
      // The dialog is titled by the finding, so the summary starts with what
      // the title does not say: its severity and description.
      h("div", {class: "detail-lede"}, badge(finding.severity),
        h("p", {class: "muted"}, finding.description || "")),
      glance(),
      caseLifecycle((finding.case || {}).state),
      h("dl", {class: "kv"},
        h("dt", {}, "Finding"), h("dd", {class: "mono"}, finding.id),
        h("dt", {}, "Store"), h("dd", {}, h("button", {class: "link", type: "button",
          onclick: () => goTo("schema", {store: storeIdFor(finding.store)})}, storeIdFor(finding.store))),
        h("dt", {}, "Collection"), h("dd", {}, finding.collection
          ? h("button", {class: "link", type: "button",
              onclick: () => goTo("schema", {store: storeIdFor(finding.store), collection: finding.collection})},
              finding.collection)
          : "store scope"),
        h("dt", {}, "Category"), h("dd", {title: finding.category || null}, finding.category ? categoryLabel(finding.category) : "-"),
        h("dt", {}, "Suppressed"), h("dd", {}, finding.suppressed ? "yes — tagged, still listed" : "no"),
        h("dt", {}, "Recorded"), h("dd", {}, formatWhen(finding.created_at)),
        h("dt", {}, "Run"), h("dd", {class: "mono"}, finding.job_id || "-"),
        h("dt", {}, "Fingerprint"), h("dd", {class: "mono"}, finding.fingerprint || "-")),
      ev.label_counts
        ? h("div", {}, h("div", {class: "metric-k"}, "Labels observed"),
            h("div", {class: "tag-row"}, Object.entries(ev.label_counts).map(([l, n]) =>
              h("span", {class: `tag sev-${spanTone(l)}`}, `${l} · ${number(n)}`))))
        : "",
      // What the scanner recommends, and the way into doing it from here.
      h("div", {class: "remediation-summary"},
        h("div", {class: "metric-k"}, "Remediation"),
        finding.remediation ? h("p", {class: "muted"}, finding.remediation) : "",
        h("button", {class: "btn small", type: "button", onclick: () => openRemediation(finding)},
          icon("shield"), "Fix this")),
      h("details", {class: "evidence-data"},
        h("summary", {}, icon("code"), "Evidence data"), jsonBlock(ev)));
  }

  function chunksTab() {
    if (!refs.length) {
      return emptyState("This finding recorded no chunk ids, so there is no chunk to open. " +
                        "Posture and configuration findings describe the store, not its content.");
    }
    return h("div", {},
      statusLine("Each row is a chunk the assessment captured as an example. Opening it fetches " +
                 "the chunk from the store as it is now, masked.", "info"),
      finding.collection
        ? h("details", {class: "evidence-data"},
            h("summary", {}, icon("play"), "Sample more of this collection, live"),
            liveSamplePanel(storeIdFor(finding.store), finding.collection))
        : "",
      table(["Chunk", "Label", "Detectors", "Matches", ""],
        refs.map(ref => h("tr", {},
          h("td", {class: "mono"}, ref.chunkId, h("div", {class: "sub"}, ref.role)),
          h("td", {}, ref.label ? h("span", {class: `tag sev-${spanTone(ref.label)}`}, ref.label) : "-"),
          h("td", {}, (ref.detectors || []).join(", ") || "-"),
          h("td", {}, ref.spans.length
            ? ref.spans.map(s => h("div", {class: "sub mono"}, s.preview || `${s.start}–${s.end}`))
            : h("span", {class: "sub"}, "-")),
          h("td", {}, h("button", {class: "btn small", type: "button",
            onclick: () => openChunk({store: finding.store, collection: finding.collection,
                                      chunkId: ref.chunkId, finding})},
            icon("eye"), "Open"))))));
  }

  function historyTab() {
    const events = detail.case_events || [];
    const same = detail.same_fingerprint || [];
    return h("div", {},
      h("div", {class: "metric-k"}, "Case changes"),
      events.length
        ? table(["When", "Who", "From", "To", "Reason"], events.map(e => h("tr", {},
            h("td", {}, formatWhen(e.at)), h("td", {}, e.actor),
            h("td", {}, e.from_state), h("td", {}, e.to_state), h("td", {}, e.reason || "-"))))
        : statusLine("No case changes recorded.", "info"),
      h("div", {class: "metric-k"}, "Same observation in other runs"),
      same.length
        ? table(["Finding", "Run", "Recorded", "Severity", "Case"], same.map(f => h("tr", {},
            h("td", {}, h("button", {class: "link mono", type: "button",
                                     onclick: () => goTo("findings", {finding: f.id})}, f.id)),
            h("td", {class: "mono"}, f.job_id || "-"),
            h("td", {}, formatWhen(f.created_at)),
            h("td", {}, badge(f.severity)),
            h("td", {}, caseBadge((f.case || {}).state)))))
        : statusLine("This fingerprint has not been recorded by another run.", "info"));
  }

  // A real tab list: one tab in the Tab order, arrows move between them, and
  // the panel is labelled by the tab that shows it. It sits in a dialog, so
  // the tabs rove: only the selected one is in the Tab order.
  async function show(key, {focus = false} = {}) {
    current = key;
    tabBar.select(key, {focus});
    const [, , render] = tabs.find(([k]) => k === key);
    content.replaceChildren(loadingState());
    const node = await render();
    if (current === key) content.replaceChildren(node);
  }
  const tabBar = tabList({id: "finding", className: "tabs detail-tabs", roving: true, panel: content,
                          tabs: tabs.map(([k, label]) => [k, label]), current,
                          onSelect: key => show(key)});

  const body = h("div", {class: "finding-detail"}, tabBar.bar, content);
  // A detail panel beside the list: titled by what was found, the id as its
  // meta, and the footer holds what to do next, not a second Close.
  modal(finding.title || finding.id, body, null, "Close", {
    stack: true, drawer: true, meta: finding.id,
    actions: [
      findingStepper(finding, reload, siblings),
      h("button", {class: "btn", type: "button", onclick: () => openRemediation(finding)},
        icon("shield"), "Fix this"),
      can("compliance")
        ? h("button", {class: "btn primary", type: "button", onclick: () => caseModal(finding, afterCaseChange)},
            icon("edit"), "Change case")
        : null,
    ].filter(Boolean),
  });
  // On Findings the open panel is part of the address: it can be copied, and
  // Back closes it. It leaves the address when the panel closes, unless the
  // address has already moved on to another finding.
  if (currentView() === "findings") {
    setParams({finding: id});
    const entry = dialogStack[dialogStack.length - 1];
    if (entry) {
      entry.onClose = () => {
        if (currentView() === "findings" && param("finding") === id) setParams({finding: ""});
      };
    }
  }
  await show("summary");
  // Arriving with fix=1 (from Actions) opens the Fix panel over the finding.
  if (param("fix") === "1") {
    setParams({fix: ""});
    openRemediation(finding);
  }
  return {body, show, finding};
}

// ===================================================================== docs ===
// One page that says what this console is, what each screen answers, and what
// it refuses to claim. Content is data so it can be checked by a test and read
// without running the app; nothing here calls the API, so it renders on a
// deployment whose backend is down.

const DOCS_SECTIONS = [
  {
    id: "what",
    title: "What this is",
    lead: "A control plane for the data inside your vector stores: what is in them, " +
          "which obligations that triggers, what was done about it, and what evidence " +
          "was collected. It governs stores you already run; it is not a vector database " +
          "and it does not sit in your retrieval path.",
    blocks: [
      {kind: "grid", items: [
        ["Inspects", "Registered vector stores, over their own connectors, read-only unless you explicitly act"],
        ["Detects", "PII, PHI, cardholder data, secrets, prompt injection, embedding anomalies, missing provenance, cross-tenant bleed, configuration posture"],
        ["Establishes", "Coverage, confidence, obligations, evidence, and who decided what"],
        ["Never claims", "That an assessment saw everything, that a detector is certain, or that a score summarises compliance"],
      ]},
      {kind: "note", tone: "medium",
       text: "The criterion pack shipped here was authored alongside the detection " +
             "rules and has had no regulatory review. It covers only obligations a " +
             "vector-store assessment can actually observe."},
    ],
  },
  {
    id: "areas",
    title: "The areas, and what each screen answers",
    lead: "Six task areas. Each screen answers one question; the tabs inside an area " +
          "are steps in the same job.",
    blocks: [{kind: "areas"}],
  },
  {
    id: "lifecycle",
    title: "The lifecycle",
    lead: "Connect, assess, review, act, evidence. Each stage produces something the " +
          "next one reads, and nothing advances on hope.",
    blocks: [
      {kind: "steps", items: [
        ["Connect", "Register a store in Estate. Its connector's capabilities decide what any result from it can mean — a store that cannot be enumerated can never be scanned for content, and the console says so rather than reporting zero findings."],
        ["Assess", "Run an assessment from Assessments → New assessment; its progress shows under Runs and the saved result under History. It walks collections, classifies chunk text and metadata, probes tenant isolation, scans RAG integrity, and checks configuration posture. Every check records its own coverage."],
        ["Review", "Findings are observations, not verdicts. Open one to see the chunk behind it, why the detector fired, and what argues against it. Give it a case state: triaged, assigned, verified, false positive, risk accepted."],
        ["Act", "Actions proposes changes — tag, quarantine, redact. A plan is staged, frozen to a hash, reviewed as a diff, approved with a reason, and only then executed. Safe mode blocks the write by default."],
        ["Evidence", "Criteria use a store's latest saved assessment; nothing new is scanned. Answer each store's questions once, add documents and have them reviewed per criterion, record exceptions for gaps you accept for now, and export a criterion's position with its caveats attached."],
      ]},
    ],
  },
  {
    id: "ideas",
    title: "The ideas the console is built on",
    lead: "Six distinctions the product exists to keep apart. Most of the interface is " +
          "downstream of them.",
    blocks: [
      {kind: "cards", items: [
        ["Coverage is not a result", "check",
         "A check that ran over part of a collection did not clear the rest. Coverage travels with every check as complete, partial, or unmeasured, and an unmeasured segment is drawn hatched rather than as zero. “We did not look” must never read as “we looked and found nothing.”"],
        ["Confidence is measured, not asserted", "info",
         "A detector reports uncertain until the benchmark measures a precision for it. Every match carries counter-signals — the reasons it might be wrong, such as a reserved example domain or a vendor test key — so a reader can judge it."],
        ["Redaction is the default", "key",
         "A finding stores offsets and a masked preview, never the text. The chunk itself is fetched live when someone asks for it. Revealing values needs the compliance role and a reason, and is written to the audit log."],
        ["An observation is not a conclusion", "alert",
         "A match becomes a violation only through a policy you scoped and enabled. A policy traces to a template, a template to a citation, a citation to a criterion — and the criterion still needs applicability answered and evidence supplied."],
        ["A case is what people decided", "user",
         "Severity is what a scan saw; the case is what your team concluded. Resolution claims (false positive, duplicate, risk accepted) are counted apart from verified work, because they assert something about the world rather than record a fix."],
        ["An exception tolerates a gap", "clock",
         "It never closes one. It names a criterion and scope, carries a rationale, is approved by someone other than the requester, expires, and when it expires the gap is open again."],
      ]},
    ],
  },
  {
    id: "evidence",
    title: "From a finding to the text behind it",
    lead: "The drill-down most reviews need: what was captured, why, and what says it " +
          "has to be reported.",
    blocks: [
      {kind: "steps", items: [
        ["Open the finding", "Findings → a row title, or the link #/findings?finding=<id>. Five tabs: Summary, Chunks, Why, Obligations, History."],
        ["Open the chunk", "The Chunks tab lists the examples the assessment captured. Opening one fetches it from the store as it is now and marks every match with its label and detector. If the chunk changed since the assessment, the drawer says so instead of painting old highlights on new text."],
        ["Read why it fired", "Beside the text: the detector, its confidence class, the reason for that class, and the counter-signals against it."],
        ["Read what says to report it", "The obligation trace: the policies that fire, the template and its citation, and the criteria this observation can inform. The last hop joins by framework and check name and is labelled as the heuristic it is."],
        ["Reveal, if you must", "Values are masked. Revealing them needs a reason, is recorded with your name, and re-masks after a minute."],
      ]},
    ],
  },
  {
    id: "crypto",
    title: "Cryptographic posture",
    lead: "Estate → Crypto reads one store's saved audit and lays out what the connector " +
          "could observe about encryption and data protection. It never scans, and it has " +
          "no score.",
    blocks: [
      {kind: "list", items: [
        "Four layers, read in order and never merged into one verdict: transport, storage encryption, field and data-level protection, and retrieval exposure.",
        "Not observable means the store's interface cannot answer. It is drawn neutral and is never a failure; a criterion that needs the property asks for fallback evidence instead, and says why.",
        "Coverage is counts (verified encrypted, verified unencrypted, unknown), never a share of a whole.",
        "Not supported means the database has no interface that reports the property at all, so the console names the database and the evidence to supply instead. Not observable means it could be reported but this run could not establish it. Not applicable means the property does not arise, such as transport encryption for a file-backed store. None of the three is a failure.",
        "Embeddings are not treated as cryptographic protection.",
        "The release gate turns one saved audit, plus evidence accepted for the store, into block, evidence needed, warn, or no rule held. It enforces nothing itself: a pipeline runs `vecshield-platform crypto-gate --store <id>`, which exits 2 on block, 1 when evidence is needed, and 0 otherwise. Evidence clears a gap; it never clears an observed failure.",
        "Disk and volume encryption, cloud key management, and IAM are not read through the database connection, so the Crypto screen makes no claim about them.",
        "Each regulation's relationship to encryption is labelled on the Crypto and Frameworks screens: Direct, Risk-based, Addressable, Control evidence, Direct where PAN is present, or Supporting evidence only.",
      ]},
    ],
  },
  {
    id: "approvals",
    title: "Approvals and safe mode",
    lead: "The only part of the product that writes to your store, and it refuses far " +
          "more often than it acts.",
    blocks: [
      {kind: "list", items: [
        "Nothing runs without an approval of that exact plan. Approval is scoped to the plan's hash, so a re-staged plan needs a fresh one.",
        "Safe mode is on by default and blocks the write. Suggesting, staging, reviewing and approving all work while it is on.",
        "Delete is implemented and gated shut: it needs every detector behind it measured at 'likely', and none is.",
        "Separation of duties is a stated policy: required, admin_may_self_approve, or off. With authentication configured the default is required; without it every caller is the same synthetic admin, so the default relaxes and every self-approval is recorded as one.",
        "An irreversible operation always needs a second person, and the approver types the store id to confirm it.",
      ]},
      {kind: "note", tone: "info",
       text: "This deployment's current setting is shown on the Status screen and " +
             "returned by /version under 'approvals'."},
    ],
  },
  {
    id: "surface",
    title: "Beyond the console",
    lead: "Everything here is API-first; the console is one client.",
    blocks: [
      {kind: "table",
       headers: ["Surface", "What it is for"],
       rows: [
         ["REST API", "Every screen's data. Same-origin, bearer token or OIDC/JWT, role-split into viewer, operator, compliance and admin."],
         ["vecshield-platform CLI", "Serving, assessments, reports, erasure, DSAR, action plans, and the detector benchmark."],
         ["vecshield CLI and SDK", "The open-source core on its own: detect, ingest-check, training-check, redact-preview."],
         ["/healthz, /livez, /readyz", "Liveness and readiness, with per-check detail."],
         ["/metrics", "Prometheus exposition."],
         ["/audit-log", "Tamper-evident record of console and API activity, including every reveal."],
       ]},
    ],
  },
  {
    id: "glossary",
    title: "Compliance words",
    lead: "Each word the Compliance screens use, defined once. A reviewed mapping describes " +
          "what we check; it does not mean your store meets the law.",
    blocks: [{kind: "glossary"}],
  },
  {
    id: "keys",
    title: "Getting around",
    lead: "",
    blocks: [
      {kind: "keys", items: [
        ["/", "Open Go to — search areas, screens, stores and frameworks"],
        ["⌘K / Ctrl-K", "The same"],
        ["↑ ↓", "Move through results"],
        ["↵", "Open the selected result"],
        ["Esc", "Close a dialog or the navigation drawer"],
      ]},
      {kind: "note", tone: "info",
       text: "Anything you can see is a link you can send: the screen, its filters, " +
             "the store and framework in scope, and the finding you are reading all " +
             "travel in the URL."},
    ],
  },
];

function docsHero() {
  return h("section", {class: "docs-hero"},
    h("div", {class: "docs-hero-plate"},
      h("img", {src: "/static/assets/vecshield-logo.png", alt: "",
                class: "docs-logo", width: "640", height: "270"})),
    h("div", {class: "docs-hero-text"},
      h("p", {class: "docs-lede"},
        "Compliance and security for vector stores — what is inside them, which " +
        "obligations that triggers, and what was decided about it."),
      h("div", {class: "bar"},
        h("button", {class: "btn small primary", type: "button", onclick: () => goTo("overview")},
          icon("grid"), "Go to the overview"),
        h("button", {class: "btn small", type: "button", onclick: () => goTo("stores")},
          icon("db"), "Connect a store"),
        h("button", {class: "btn small", type: "button", onclick: () => goTo("frameworks")},
          icon("layers"), "What the frameworks require"))));
}

function docsBlock(block) {
  if (block.kind === "note") return statusLine(block.text, block.tone || "info");
  if (block.kind === "list") {
    return h("ul", {class: "docs-list"}, block.items.map(text => h("li", {}, text)));
  }
  if (block.kind === "grid") {
    return h("dl", {class: "docs-grid"}, block.items.flatMap(([term, detail]) =>
      [h("dt", {}, term), h("dd", {}, detail)]));
  }
  if (block.kind === "steps") {
    return h("ol", {class: "docs-steps"}, block.items.map(([name, detail]) =>
      h("li", {}, h("span", {class: "strong"}, name), h("p", {}, detail))));
  }
  if (block.kind === "cards") {
    return h("div", {class: "docs-cards"}, block.items.map(([title, glyph, detail]) =>
      h("article", {class: "docs-card"},
        h("div", {class: "docs-card-head"}, icon(glyph), h("h3", {}, title)),
        h("p", {}, detail))));
  }
  if (block.kind === "glossary") return termList(Object.keys(COMPLIANCE_TERMS));
  if (block.kind === "keys") {
    return h("dl", {class: "docs-keys"}, block.items.flatMap(([key, detail]) =>
      [h("dt", {}, h("kbd", {}, key)), h("dd", {}, detail)]));
  }
  if (block.kind === "table") {
    return table(block.headers, block.rows.map(row =>
      h("tr", {}, row.map((cell, index) =>
        h("td", {class: index === 0 ? "strong" : ""}, cell)))));
  }
  // The areas are not restated here: they are read from the registry, so this
  // page cannot drift from the navigation it describes.
  if (block.kind === "areas") {
    return h("div", {class: "docs-areas"}, AREAS.map(([name, glyph, blurb, members]) =>
      h("article", {class: "docs-area"},
        h("div", {class: "docs-card-head"}, icon(glyph),
          h("h3", {}, h("button", {class: "link", type: "button",
                                   onclick: () => goTo(members[0])}, name))),
        h("p", {class: "muted"}, blurb),
        h("dl", {class: "docs-screens"}, members.flatMap(id => [
          h("dt", {}, h("button", {class: "link", type: "button",
                                   onclick: () => goTo(id)}, views[id][0])),
          h("dd", {}, views[id][1]),
        ])))));
  }
  return "";
}

async function renderDocs() {
  const box = h("div", {class: "docs"});
  box.append(pageHeader("docs"));
  box.append(docsHero());

  // A jump list rather than anchors: the hash already carries the route, so an
  // in-page anchor would fight the router.
  box.append(h("nav", {class: "docs-toc", "aria-label": "On this page"},
    h("span", {class: "metric-k"}, "On this page"),
    h("ul", {}, DOCS_SECTIONS.map(section =>
      h("li", {}, h("button", {class: "link", type: "button",
                               onclick: () => document.getElementById(`docs-${section.id}`)
                                 ?.scrollIntoView?.({block: "start", behavior: "smooth"})},
        section.title))))));

  for (const section of DOCS_SECTIONS) {
    box.append(panel(section.title, [
      section.lead ? h("p", {class: "docs-lead"}, section.lead) : "",
      ...section.blocks.map(docsBlock)], null, {className: "docs-section", id: `docs-${section.id}`}));
  }

  box.append(statusLine(
    "This page describes the console as it is built, not as it is planned. " +
    "Where it and the product disagree, the product is right and this is a bug.",
    "medium"));
  return box;
}

function boot() {
  // theme.js has already applied the theme in the browser. A stored choice is
  // re-applied for pages that load the console without it; with nothing
  // stored, whatever the page already set stands.
  const saved = storedTheme();
  if (saved) document.documentElement.dataset.theme = saved;
  // Registered here rather than with the shell so the sign-in screen follows
  // the system too. Only a console with no stored choice follows it.
  globalThis.matchMedia?.("(prefers-color-scheme: dark)")?.addEventListener?.("change", event => {
    if (!storedTheme()) applyTheme(event?.matches ? "dark" : "light");
  });
  // The compact density toggle is gone; a stale preference must not survive it.
  try { localStorage.removeItem("vecshield_density"); } catch { /* private mode */ }
  delete document.documentElement.dataset.density;
  window.addEventListener("hashchange", route);
  window.addEventListener("beforeunload", event => {
    if (leaveGuard?.dirty?.()) { event.preventDefault?.(); event.returnValue = ""; }
  });
  // Ask who is signed in before drawing anything: a console that needs a
  // sign-in shows that screen, not a flash of failed requests.
  return startConsole();
}

boot();
