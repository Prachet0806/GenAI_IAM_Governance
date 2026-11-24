CREATE TRIGGER immutable_collection_receipt_update
    BEFORE UPDATE ON collection_receipts BEGIN
    SELECT RAISE(ABORT, 'collection receipts are immutable');
END;
CREATE TRIGGER immutable_collection_receipt_delete
    BEFORE DELETE ON collection_receipts BEGIN
    SELECT RAISE(ABORT, 'collection receipts are immutable');
END;
