ALTER TABLE grant_paths DROP CONSTRAINT grant_paths_grant_type_check;
ALTER TABLE grant_paths ADD CONSTRAINT grant_paths_grant_type_check CHECK (
    grant_type IN ('DIRECT_MANAGED','DIRECT_INLINE','GROUP_MANAGED','GROUP_INLINE',
                   'ROLE_MANAGED','ROLE_INLINE','ROLE_TRUST',
                   'IDENTITY_CENTER_ASSIGNMENT')
);
