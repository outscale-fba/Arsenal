# AWS KMS connector

Allow to use AWS KMS backend for encryption of objects. It currently only support AK+SK for authentication.

## Configuration

Configuration is done using the configuration file or environment variables. A Mix of both can be used, the configuration file takes precedence over environment variables.
Environment variables are the same as the ones used by the AWS CLI.

The following parameters are supported:

| config file         | env variable                             | Description
|---------------------|------------------------------------------|------------
| kmsAws.region       | AWS_REGION or AWS_DEFAULT_REGION         | AWS region tu use
| kmsAws.endpoint     | AWS_ENDPOINT_URL_KMS or AWS_ENDPOINT_URL | Endpoint URL
| kmsAws.ak           | AWS_ACCESS_KEY_ID                        | Credentials, Access Key
| kmsAws.sk           | AWS_SECRET_ACCESS_KEY                    | Credentials, Secret Key
| kmsAws.perUserKey   | -                                        | Use per-user keys instead of per bucket keys (see below)

Configuration example:
```json
    "kmsAws": {
        "region": "us-east-1",
        "endpoint": "https://kms.us-east-1.amazonaws.com",
        "ak": "xxxxxxx",
        "sk": "xxxxxxx",
        "perUserKey": false
    },
```

## Specific Features

### Per user keys

This connector allows to use per-user keys instead of per-bucket.

This feature is configured by the `kmsAws/perUserKey` parameter in the configuration file.
When this parameter is set to `true`, keys are created on a per-user basis instead of per-bucket.

Behind the hood, it uses the Alias feature of AWS. Each user, identified by its canonical ID,
have a unique key and an alias "alias/s3user-<canonicalId>" on this key. This alias is used as a key ID,
this allows to deduce the key ID (= the alias) from the user ID and reuse it accross the buckets.

When encryption is activated on a bucket, it will:
- Check for an existing alias for the user's key. If an alias exists it is returned immediatly and the process stops there.
- If no alias exists, a new key is created for the user and an alias is also created. This alias is returned as a key ID.

When a bucket with encryption is deleted, this connector detects if an alias (ie user keys) was used. If so, the key and alias are not removed, because they may be used by other buckets.

This connector won't delete user keys. This would need to detect a user deletion, wich is not feasible in the cloudserver component.
This is not issue when handling a small number of users. However you can still handle this separatly.