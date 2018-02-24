// Copyright (c) 2018 AccelByte, Inc. All Right Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"

	"net/url"

	"strings"

	"crypto/md5"

	"encoding/hex"

	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type BitbucketRepo struct {
	Name string `json:"name"`
}

type BitbucketPaginated struct {
	Next   string `json:"next"`
	Values []BitbucketRepo
}

func GetAccessToken(clientID string, clientSecret string, grantUrl string) (string, error) {
	client := &http.Client{}
	grant := bytes.NewBufferString(url.Values{"grant_type": {"client_credentials"}}.Encode())
	req, err := http.NewRequest(http.MethodPost, grantUrl, grant)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", errors.New("request failed: " + err.Error())
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("unexpected response: " + err.Error())
	}

	var token struct {
		Access string `json:"access_token"`
	}
	err = json.Unmarshal(body, &token)
	if err != nil {
		return "", errors.New("unable to decode token: " + err.Error())
	}

	return token.Access, nil
}

func ComputeMD5Hash(data []byte) string {
	hash := md5.Sum([]byte(data))
	text := hex.EncodeToString(hash[:])
	return text
}

func main() {
	clientID := os.Getenv("BITBUCKET_OAUTH_CLIENT_ID")
	if clientID == "" {
		logrus.Fatal("BITBUCKET_OAUTH_CLIENT_ID not set")
	}
	clientSecret := os.Getenv("BITBUCKET_OAUTH_CLIENT_SECRET")
	if clientSecret == "" {
		logrus.Fatal("BITBUCKET_OAUTH_CLIENT_SECRET not set")
	}
	team := os.Getenv("BITBUCKET_TEAM")
	if team == "" {
		logrus.Fatal("BITBUCKET_TEAM not set")
	}
	s3bucket := os.Getenv("AWS_S3BUCKET_NAME")
	if s3bucket == "" {
		s3bucket = team + "-bitbucket-backups"
	}
	awsRegion := os.Getenv("AWS_REGION")
	if awsRegion == "" {
		awsRegion = "us-west-2"
	}
	logLevel := logrus.InfoLevel
	logParam := os.Getenv("LOG_LEVEL_NUMBER")
	if logParam != "" {
		tmp, _ := strconv.ParseInt(logParam, 10, 32)
		logLevel = logrus.Level(tmp)
	}
	logrus.SetLevel(logLevel)

	// Bitbucket OAuth Token
	token, err := GetAccessToken(clientID, clientSecret, "https://bitbucket.org/site/oauth2/access_token")
	if err != nil {
		logrus.Fatal("Unable to login get Bitbucket OAuth access token: ", err.Error())
	}

	// AWS Sessions
	sess, err := session.NewSession(&aws.Config{Region: aws.String(awsRegion)})
	if err != nil {
		logrus.Fatal("Unable to create AWS session:", err)
	}
	uploader := s3manager.NewUploader(sess)
	s3metadata := s3.New(sess)

	// Query list of repos form Bitbucket
	var repoNames []string
	NextPage := fmt.Sprintf("https://api.bitbucket.org/2.0/teams/%s/repositories/", team)
	for NextPage != "" {
		client := &http.Client{}
		req, err := http.NewRequest(http.MethodGet, NextPage, nil)
		req.Header.Add("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			logrus.Fatal("Unable to get repository list: err=", err, " resp=", resp)
		}

		var pagedRepos BitbucketPaginated
		body, err := ioutil.ReadAll(resp.Body)
		logrus.Debug("Repository Page: ", string(body))
		json.Unmarshal(body, &pagedRepos)
		for _, repo := range pagedRepos.Values {
			repoNames = append(repoNames, repo.Name)
		}
		NextPage = pagedRepos.Next
	}

	repoCount := len(repoNames)
	repoBackupOKCount := 0
	repoBackupUnchanged := 0

	logrus.Info("Team: ", team)
	logrus.Info("Repo Count: ", repoCount)
	logrus.Info("Repo Names: ", repoNames)

	if repoCount < 1 {
		logrus.Fatal("No repositories found to backup")
	}

	// Clean up previous stale runs
	for _, delete := range repoNames {
		os.Remove(delete + ".bundle")
		os.RemoveAll(delete)
	}

	// Backup repos
	for _, name := range repoNames {

		// Mirror repo locally
		repoUrl := fmt.Sprintf("https://x-token-auth:%s@bitbucket.org/%s/%s", token, team, name)
		cmd := exec.Command("git", "--no-pager", "clone", "--mirror", repoUrl, name)
		output, err := cmd.CombinedOutput()
		if err != nil {
			logrus.Error(cmd.Args, ": ", name, ":", err, " ", string(output))
			continue
		}

		// Compute hash of log for comparisons later to determine if we need to backup the repo
		// NB: We can't take a md5 of the bundle or whole repo because the pack files
		// change due to git's housekeeping
		os.Chdir(name)
		cmd = exec.Command("git", "--no-pager", "log", "--all", "--format=format:%H")
		output, err = cmd.Output()
		os.Chdir("..")
		if err != nil {
			logrus.Error(cmd.Args, name, ":", err, " ", string(output))
			continue
		}
		commitCount := bytes.Count(output, []byte("\n"))
		hash := ComputeMD5Hash(output)

		// Determine if repo has changed since last backup
		bundle := name + ".bundle"
		input := &s3.HeadObjectInput{
			Bucket: aws.String(s3bucket),
			Key:    aws.String(bundle),
		}
		info, err := s3metadata.HeadObject(input)
		if err == nil {
			compare := "none"
			if md5, ok := info.Metadata["Git-Log-All-Format-H"]; ok {
				compare = *md5
			}
			if hash == compare {
				logrus.Debug("Unchanged git log for repo ", name, "(md5:", hash, "<->", compare, ", commitCount:", commitCount, ")")
				os.RemoveAll(name)
				repoBackupUnchanged++
				continue
			}
			logrus.Debug("Changed git log for repo ", name, "(md5:", hash, "<->", compare, ", commitCount:", commitCount, ")")
		}

		// Housekeeping to keep size down
		cmd = exec.Command("git", "gc")
		output, err = cmd.CombinedOutput()
		if err != nil {
			logrus.Error(cmd.Args, ": ", name, ":", err, " ", string(output))
			continue
		}

		// Create git bundle
		os.Chdir(name)
		cmd = exec.Command("git", "bundle", "create", "../"+bundle, "--all")
		output, err = cmd.CombinedOutput()
		os.Chdir("..")
		if err != nil {
			logrus.Error(cmd.Args, ": ", name, ":", err, " ", string(output))
			continue
		}

		// Verify git bundle
		os.Chdir(name)
		cmd = exec.Command("git", "bundle", "verify", "../"+bundle)
		output, err = cmd.CombinedOutput()
		os.Chdir("..")
		if err != nil {
			logrus.Error(cmd.Args, ": ", name, ":", err, " ", string(output))
			continue
		}

		// Get list of branches to add as metadata to backup S3 object
		cmd = exec.Command("git", "bundle", "list-heads", bundle)
		output, err = cmd.Output()
		if err != nil {
			logrus.Error("git bundle: ", name, ":", err, " ", string(output))
		}
		// list-heads output that is parsed below:
		// 71881475e6b19a6369fb94526cf6b0bf397c10f6 refs/heads/PJ-212-cleanup-and-optimize-on-decoder-p
		// 116b8adba08b269d53f6e2ad6a59b267e51c0942 refs/heads/PJ-223-crash-video-download-link-process
		// b95ab8477784c2e8a6a341b2c0e578d9ee45fdae refs/heads/PJ-261-build-version-for-decoder-process
		// 8c27b12901b86d0a520b2e63ab8dc4861ad69d96 refs/heads/PJ-267-fix-error-and-warning-from-linter
		// 6060332bdee2f4e4f3a0a83371c6c2babe8024e9 refs/heads/build-system
		// 15274c3b5965705c68d068ad12f9ddbd6f5989aa refs/heads/jenkinsfile
		// 0a3eaa477ab7d923a8d45bfcb4f6aaa82ac9ee98 refs/heads/master
		// 92d92efc3484c01ab7a0b9f1fee698db9de27693 refs/heads/prefix-s3
		// 0a3eaa477ab7d923a8d45bfcb4f6aaa82ac9ee98 HEAD

		// Parse git heads above
		tmp := strings.TrimSpace(string(output))
		gitHeads := strings.Split(tmp, "\n")

		s3metaHeaderSize := 0
		s3metaHeader := map[string]*string{}

		// Track hash of git sha's for determining if the repo has changed
		s3metaHeaderSize += len("Git-Log-All-Format-H") + len(": ") + len(hash)
		s3metaHeader["Git-Log-All-Format-H"] = &hash

		// Add git branches to metadata on s3 object
		for i, _ := range gitHeads {
			line := gitHeads[len(gitHeads)-i-1]
			s := strings.Split(line, " ")

			value := url.PathEscape(s[0])
			key := "Git-" + url.PathEscape(s[1])

			// max meta data header size in bytes is 2KB
			s3metaHeaderSize += len(key) + len(": ") + len(value)
			if s3metaHeaderSize >= 2*1024 {
				logrus.Warn("Bundle has too many branches to add to the s3 object's metadata, truncating 2KB: ", bundle)
				break
			}
			s3metaHeader[key] = &value
		}

		// Upload bundle to s3
		fd, err := os.Open(bundle)
		if err != nil {
			logrus.Error("unable to open bundle for upload: ", bundle, " ", err)
			continue
		}
		defer fd.Close()

		uploader.PartSize = s3manager.MinUploadPartSize
		_, err = uploader.Upload(&s3manager.UploadInput{
			Bucket:       aws.String(s3bucket),
			Key:          aws.String(bundle),
			Body:         fd,
			Metadata:     s3metaHeader,
			StorageClass: aws.String(s3.StorageClassStandardIa),
		})
		if err != nil {
			logrus.Error("unable to upload bundle to s3 bucket: ", bundle, ": ", s3bucket, ": ", err)
			continue
		}

		// Clean up
		os.Remove(bundle)
		os.RemoveAll(name)

		logrus.Debug("Backed up " + bundle + " to s3://" + s3bucket + "/" + bundle + " " + "(" + hash + ") OK")
		repoBackupOKCount++
	}

	repoBackupFailures := repoCount - repoBackupOKCount - repoBackupUnchanged
	report := fmt.Sprintf("OK: %d, Unchangd: %d, Fail: %d",
		repoBackupOKCount, repoBackupUnchanged, repoBackupFailures)
	if repoBackupFailures == 0 {
		logrus.Info(report)
	} else {
		logrus.Fatal(report)
	}
}
