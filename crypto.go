/* ----------------------------------------------------------------------
 *       ______      ___                         __
 *      / ____/___  /   |  ____  __  ___      __/ /_  ___  ________
 *     / / __/ __ \/ /| | / __ \/ / / / | /| / / __ \/ _ \/ ___/ _ \
 *    / /_/ / /_/ / ___ |/ / / / /_/ /| |/ |/ / / / /  __/ /  /  __/
 *    \____/\____/_/  |_/_/ /_/\__. / |__/|__/_/ /_/\___/_/   \___/
 *                            /____/
 *
 * (C) Copyright 2015 GoAnywhere (http://goanywhere.io).
 * ----------------------------------------------------------------------
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * ----------------------------------------------------------------------*/
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Random creates a URL-safe random string which is based on
// the implementation with cryptographically secure pseudorandom number.
func Random(length int) string {
	key := make([]byte, length)
	io.ReadFull(rand.Reader, key)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(key), "=")[0:length]
}

// mixin creates secret hashed string for the source using the given key.
func mixin(src string) []byte {
	if secret := os.Getenv("SECRET_KEY"); secret != "" {
		hash := hmac.New(sha1.New, []byte(secret))
		hash.Write([]byte(src))
		return hash.Sum(nil)
	}
	return []byte(src)
}

// Encrypt creates a new password hash using a strong one-way bcrypt algorithm.
// Source secret is hashed with the given key (if set) before actual bcrypting.
func Encrypt(src string) (secret string) {
	bytes, err := bcrypt.GenerateFromPassword(mixin(src), bcrypt.DefaultCost)
	if err == nil {
		secret = string(bytes)
	}
	return
}

// Verify checks that if the given hash matches the given source secret.
// Source secret is hashed with the given key (if set) before actual bcrypting.
func Verify(src, secret string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(secret), mixin(src))
	if err == nil {
		return true
	}
	return false
}
