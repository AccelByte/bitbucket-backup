// Copyright (c) 2018 AccelByte, Inc. All Rights Reserved.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/sirupsen/logrus"
)

type BitbucketOAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
}

type BitbucketRepo struct {
	Name string `json:"name"`
}

type BitbucketPaginated struct {
	Next   string `json:"next"`
	Values []BitbucketRepo
}

func main() {

	s3bucket := os.Getenv("S3BUCKET_NAME")

	// AWS Sessions
	sess, err := session.NewSession(&aws.Config{Region: aws.String(os.Getenv("AWS_REGION"))})
	if err != nil {
		logrus.Fatal("Unable to create AWS session:", err)
	}
	uploader := s3manager.NewUploader(sess)

	// Bitbucket OAuth Token
	client := &http.Client{}
	grant := bytes.NewBufferString(url.Values{"grant_type": {"client_credentials"}}.Encode())
	req, err := http.NewRequest(http.MethodPost, "https://bitbucket.org/site/oauth2/access_token", grant)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("8qf82YrTfkAmw7WPGF", "5LhrEjr5PA5QsxAJB6mjhRTjtaTMadrJ")
	resp, err := client.Do(req)
	if err != nil {
		logrus.Fatal("Unable to obtain Bitbucket OAuth token:", err, resp)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatal("Unable to read Bitbucket OAuth token grant HTTP repsonse body:", err)
	}
	var token BitbucketOAuthTokenResponse
	err = json.Unmarshal(body, &token)
	if err != nil {
		logrus.Fatal("Unable to decode Bitbucket OAuth token json response:", err)
	}

	// Query list of repos form Bitbucket
	var repoNames []string
	NextPage := "https://api.bitbucket.org/2.0/teams/accelbyte/repositories/"
	for NextPage != "" {

		req, err = http.NewRequest(http.MethodGet, NextPage, nil)
		req.Header.Add("Authorization", "Bearer "+token.AccessToken)
		resp, err = client.Do(req)
		if err != nil {
			panic("request failed")
		}

		var pagedRepos BitbucketPaginated
		body, err = ioutil.ReadAll(resp.Body)
		json.Unmarshal(body, &pagedRepos)
		for _, repo := range pagedRepos.Values {
			repoNames = append(repoNames, repo.Name)
		}
		NextPage = pagedRepos.Next
	}

	repoCount := len(repoNames)
	repoBackupOKCount := 0

	logrus.Info("Repo Count: ", len(repoNames))
	logrus.Info("Repo Names: ", repoCount)

	// Backup repos
	for _, name := range repoNames {

		repoUrl := fmt.Sprintf("https://x-token-auth:%s@bitbucket.org/accelbyte/%s", token.AccessToken, name)
		cmd := exec.Command("git", "clone", "--mirror", repoUrl, name)
		output, err := cmd.CombinedOutput()
		if err != nil {
			logrus.Error("git clone mirror ", name, ":", err, " ", string(output))
			continue
		}

		bundle := name + ".bundle"
		os.Chdir(name)
		cmd = exec.Command("git", "bundle", "create", "../"+bundle, "--all")
		output, err = cmd.CombinedOutput()
		os.Chdir("..")
		if err != nil {
			logrus.Error("git bundle create: ", name, ":", err, " ", string(output))
			continue
		}

		os.Chdir(name)
		cmd = exec.Command("git", "bundle", "verify", "../"+bundle)
		output, err = cmd.CombinedOutput()
		os.Chdir("..")
		if err != nil {
			logrus.Error("git bundle verify: ", name, ":", err, " ", string(output))
			continue
		}

		t := time.Now()
		date := fmt.Sprintf("%02d/%02d/%02d/%02d-%02d-%02d",
			t.Day(), t.Month(), t.Year(),
			t.Day(), t.Month(), t.Year())
		s3object := date + "-" + bundle

		fd, err := os.Open(bundle)
		if err != nil {
			logrus.Error("unable to open bundle for upload: ", bundle, " ", err)
			continue
		}
		defer fd.Close()

		_, err = uploader.Upload(&s3manager.UploadInput{
			Bucket: aws.String(s3bucket),
			Key:    aws.String(s3object),
			Body:   fd,
		})
		if err != nil {
			logrus.Error("unable to upload bundle to s3 bucket: ", bundle, s3bucket)
			continue
		}

		// Clean up
		os.Remove(bundle)
		os.RemoveAll(name)

		logrus.Debug("Backed up " + bundle + " to s3://" + s3bucket + "/" + s3object + " OK")
		repoBackupOKCount++
	}

	repoBackupFailures := repoBackupOKCount - repoCount
	if repoBackupFailures == 0 {
		logrus.Info("OK: %d, Fail: %d", repoBackupOKCount, repoBackupFailures)
	} else {
		logrus.Fatal("OK: %d, Fail: %d", repoBackupOKCount, repoBackupFailures)
	}
}
