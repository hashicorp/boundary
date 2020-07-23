syntax = "proto3";

package controller.storage.jobs.store.v1;
option go_package = "github.com/hashicorp/watchtower/internal/jobs/store;store";

import "google/protobuf/timestamp.proto";

// Job contains all fields related to a Job resource
message Job {
  // public_id is used to access the Role via an API
  // @inject_tag: gorm:"primary_key"
  string public_id = 10;

  // pending_time from the RDBMS
  // @inject_tag: `gorm:"default:current_timestamp"`
  timestamp.v1.Timestamp pending_time = 20;

  // active_time from the RDBMS
  // @inject_tag: `gorm:"default:current_timestamp"`
  timestamp.v1.Timestamp active_time = 30;

  // canceling_time from the RDBMS
  // @inject_tag: `gorm:"default:current_timestamp"`
  timestamp.v1.Timestamp canceling_time = 40;

  // canceled_time from the RDBMS
  // @inject_tag: `gorm:"default:current_timestamp"`
  timestamp.v1.Timestamp canceled_time = 50;

  // complete_time from the RDBMS
  // @inject_tag: `gorm:"default:current_timestamp"`
  timestamp.v1.Timestamp complete_time = 60;

  // Type of job
  // @inject_tag: `gorm:"default:null"`
  string job_type = 70;

  // Name of worker
  // @inject_tag: `gorm:"default:null"`
  string worker_name = 80;
}