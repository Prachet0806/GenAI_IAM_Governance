CREATE TRIGGER immutable_collection_receipts
    BEFORE UPDATE OR DELETE ON collection_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
