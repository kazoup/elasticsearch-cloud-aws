/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.gateway.s3;

import com.amazonaws.services.s3.model.EncryptionMaterials;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchIllegalArgumentException;
import org.elasticsearch.cloud.aws.AwsS3Service;
import org.elasticsearch.cloud.aws.blobstore.S3BlobStore;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.Base64;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.gateway.blobstore.BlobStoreGateway;
import org.elasticsearch.index.gateway.s3.S3IndexGatewayModule;
import org.elasticsearch.repositories.RepositoryException;
import org.elasticsearch.threadpool.ThreadPool;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 *
 */
public class S3Gateway extends BlobStoreGateway {

    private final ExecutorService concurrentStreamPool;

    @Inject
    public S3Gateway(Settings settings, ThreadPool threadPool, ClusterService clusterService,
                     ClusterName clusterName, AwsS3Service s3Service) throws IOException {
        super(settings, threadPool, clusterService, clusterName);

        String bucket = componentSettings.get("bucket");
        if (bucket == null) {
            throw new ElasticsearchIllegalArgumentException("No bucket defined for s3 gateway");
        }

        String clientSideEncryptionSymmetricKeyBase64 = componentSettings.get("client_side_encryption_key.symmetric");
        String clientSideEncryptionPublicKeyBase64 = componentSettings.get("client_side_encryption_key.public");
        String clientSideEncryptionPrivateKeyBase64 = componentSettings.get("client_side_encryption_key.private");
        EncryptionMaterials clientSideEncryptionMaterials = null;
        if (clientSideEncryptionSymmetricKeyBase64 != null && (clientSideEncryptionPublicKeyBase64 != null || clientSideEncryptionPrivateKeyBase64 != null)) {
            throw new ElasticsearchIllegalArgumentException("Client-side encryption: You can't specify an symmetric key AND a public/private key pair");
        }
        if (clientSideEncryptionSymmetricKeyBase64 != null) {
            try {
                if (javax.crypto.Cipher.getMaxAllowedKeyLength("AES") < 256) {
                    throw new ElasticsearchIllegalArgumentException("Client-side encryption: Please install the Java Cryptography Extension");
                }

                byte[] symmetricKeyBytes = Base64.decode(clientSideEncryptionSymmetricKeyBase64);
                SecretKeySpec symmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");
                clientSideEncryptionMaterials = new EncryptionMaterials(symmetricKey);
            } catch (IllegalArgumentException e) {
                throw new ElasticsearchIllegalArgumentException("Client-side encryption: Error decoding your symmetric key: " + e.getMessage());
            } catch (NoSuchAlgorithmException e) {
                throw new ElasticsearchIllegalArgumentException(e.getMessage());
            }
        }
        if (clientSideEncryptionPublicKeyBase64 != null || clientSideEncryptionPrivateKeyBase64 != null) {
            if(clientSideEncryptionPublicKeyBase64 == null || clientSideEncryptionPrivateKeyBase64 == null) {
                throw new ElasticsearchIllegalArgumentException("Client-side encryption: Please specify a public AND a private key, not just one of them.");
            }
            try {
                if (javax.crypto.Cipher.getMaxAllowedKeyLength("AES") < 256) {
                    throw new ElasticsearchIllegalArgumentException("Client-side encryption: Please install the Java Cryptography Extension");
                }

                final byte[] publicKeyBytes = Base64.decode(clientSideEncryptionPublicKeyBase64);
                PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                final byte[] privateKeyBytes = Base64.decode(clientSideEncryptionPrivateKeyBase64);
                PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
                KeyPair keyPair = new KeyPair(publicKey, privateKey);
                clientSideEncryptionMaterials = new EncryptionMaterials(keyPair);
            } catch (IllegalArgumentException e) {
                throw new ElasticsearchIllegalArgumentException("Client-side encryption: Error decoding your public/private keys: " + e.getMessage());
            } catch (NoSuchAlgorithmException e) {
                throw new ElasticsearchIllegalArgumentException(e.getMessage());
            } catch (InvalidKeySpecException e) {
                throw new ElasticsearchIllegalArgumentException( e.getMessage());
            }
        }
        String region = componentSettings.get("region");
        if (region == null) {
            if (settings.get("cloud.aws.region") != null) {
                String regionSetting = settings.get("cloud.aws.region");
                if ("us-east".equals(regionSetting.toLowerCase())) {
                    region = null;
                } else if ("us-east-1".equals(regionSetting.toLowerCase())) {
                    region = null;
                } else if ("us-west".equals(regionSetting.toLowerCase())) {
                    region = "us-west-1";
                } else if ("us-west-1".equals(regionSetting.toLowerCase())) {
                    region = "us-west-1";
                } else if ("us-west-2".equals(regionSetting.toLowerCase())) {
                    region = "us-west-2";
                } else if ("ap-southeast".equals(regionSetting.toLowerCase())) {
                    region = "ap-southeast-1";
                } else if ("ap-southeast-1".equals(regionSetting.toLowerCase())) {
                    region = "ap-southeast-1";
                } else if ("ap-southeast-2".equals(regionSetting.toLowerCase())) {
                    region = "ap-southeast-2";
                } else if ("ap-northeast".equals(regionSetting.toLowerCase())) {
                    region = "ap-northeast-1";
                } else if ("ap-northeast-1".equals(regionSetting.toLowerCase())) {
                    region = "ap-northeast-1";
                } else if ("eu-west".equals(regionSetting.toLowerCase())) {
                    region = "EU";
                } else if ("eu-west-1".equals(regionSetting.toLowerCase())) {
                    region = "EU";
                } else if ("sa-east".equals(regionSetting.toLowerCase())) {
                    region = "sa-east-1";
                } else if ("sa-east-1".equals(regionSetting.toLowerCase())) {
                    region = "sa-east-1";
                }
            }
        }
        ByteSizeValue chunkSize = componentSettings.getAsBytesSize("chunk_size", new ByteSizeValue(100, ByteSizeUnit.MB));

        int concurrentStreams = componentSettings.getAsInt("concurrent_streams", 5);
        this.concurrentStreamPool = EsExecutors.newScaling(1, concurrentStreams, 5, TimeUnit.SECONDS, EsExecutors.daemonThreadFactory(settings, "[s3_stream]"));

        logger.debug("using bucket [{}], region [{}], chunk_size [{}], concurrent_streams [{}]", bucket, region, chunkSize, concurrentStreams);

        initialize(new S3BlobStore(settings, s3Service.client(clientSideEncryptionMaterials), bucket, region, concurrentStreamPool), clusterName, chunkSize);
    }

    @Override
    protected void doClose() throws ElasticsearchException {
        super.doClose();
        concurrentStreamPool.shutdown();
    }

    @Override
    public String type() {
        return "s3";
    }

    @Override
    public Class<? extends Module> suggestIndexGateway() {
        return S3IndexGatewayModule.class;
    }
}
