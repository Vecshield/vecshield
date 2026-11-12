# FAQ

## Does VecShield send data to a service?

No. The `vecshield` library runs in your process. It does not call a VecShield
service and does not send telemetry.

## Is VecShield a compliance product?

The `vecshield` library is a local safety gate. It can help enforce data-handling
policy before embedding or training, but it is not a legal determination or a
complete compliance workflow.

## Should I block or redact?

Block when a chunk should not enter the vector store at all. Redact when the
surrounding context is useful and the sensitive substring can be removed safely.

## Why gate after chunking?

The embedding model sees chunks, not original documents. Gate the exact text
that would be embedded so policy decisions match the persisted vector records.

## Can I add custom detectors?

Yes. Implement `Classifier.classify()` and pass your classifier to
`check_text()` or `check_chunks()`. See [examples/custom_detector.py](../../examples/library/custom_detector.py).

## Can I scan cloud object stores directly?

Community focuses on local files and local pipeline gates. For cloud object
stores, export or stage data locally before scanning it with `ingest-check` or
`training-check`.
