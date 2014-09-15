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

package org.elasticsearch.cloud.aws.blobstore;

import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectResult;
import org.elasticsearch.common.blobstore.BlobPath;
import org.elasticsearch.common.blobstore.ImmutableBlobContainer;
import org.elasticsearch.common.blobstore.support.BlobStores;
import org.elasticsearch.common.primitives.Longs;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.io.SequenceInputStream;
import java.security.Key;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

/**
 *
 */
public class S3ImmutableBlobContainer extends AbstractS3BlobContainer implements ImmutableBlobContainer {

    public S3ImmutableBlobContainer(BlobPath path, S3BlobStore blobStore) {
        super(path, blobStore);
    }

    @Override
    public void writeBlob(final String blobName, final InputStream is, final long sizeInBytes, final WriterListener listener) {
        blobStore.executor().execute(new Runnable() {
            @Override
            public void run() {
                try {
                    InputStream blobInputStream = is;
                    long newSizeInBytes = sizeInBytes;

                    String clientSideEncryptionKey = blobStore.getClientSideEncryptionKey();
                    if(clientSideEncryptionKey != null) {

                        byte[] encryptionKeyValue = DatatypeConverter.parseHexBinary(clientSideEncryptionKey);
                        Key encryptionKey = new SecretKeySpec(encryptionKeyValue, "AES");
                        Cipher cipher = Cipher.getInstance("AES");
                        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);

                        // AES uses blocks of 16 bytes, so the size of the input stream has to be a multiple of 16.
                        // The original size of the content and some padding bytes will be added at the beginning
                        // of the stream. The size will be used in the decryption to know how many bytes have
                        // to be skipped.
                        long totalSizeWithoutPaddingInBytes = Long.SIZE / 8 + sizeInBytes;
                        long paddingSizeInBytes = 0;
                        if(totalSizeWithoutPaddingInBytes % cipher.getBlockSize() > 0) {
                            paddingSizeInBytes = cipher.getBlockSize() - totalSizeWithoutPaddingInBytes % cipher.getBlockSize();
                        }

                        blobInputStream = new SequenceInputStream(
                            new SequenceInputStream(
                                    new ByteArrayInputStream(Longs.toByteArray(sizeInBytes)),
                                    new ByteArrayInputStream(new byte[(int) paddingSizeInBytes])
                            ),
                            is
                        );

                        // When decrypting the file, the last block won't be read so we need to add an extra block.
                        // It could be because the stream is not closed properly.
                        // Could this be avoided?
                        newSizeInBytes = paddingSizeInBytes + totalSizeWithoutPaddingInBytes + cipher.getBlockSize();

                        // Encryption
                        blobInputStream = new CipherInputStream(blobInputStream, cipher);
                    }

                    ObjectMetadata md = new ObjectMetadata();
                    md.setContentLength(newSizeInBytes);
                    PutObjectResult objectResult = blobStore.client().putObject(blobStore.bucket(), buildKey(blobName), blobInputStream, md);
                    listener.onCompleted();
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }
        });
    }

    @Override
    public void writeBlob(String blobName, InputStream is, long sizeInBytes) throws IOException {
        BlobStores.syncWriteBlob(this, blobName, is, sizeInBytes);
    }
}
