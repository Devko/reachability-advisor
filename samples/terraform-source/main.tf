resource "google_cloud_run_service" "audit" {
  name = "audit-api"
  template {
    spec {
      containers {
        image = "gcr.io/acme/audit-api:1.0.0"
      }
    }
  }
}

resource "google_cloud_run_service_iam_member" "public" {
  service = google_cloud_run_service.audit.name
  role    = "roles/run.invoker"
  member  = "allUsers"
}

module "example_child_module" {
  source = "example/module"
  image  = var.image
}
