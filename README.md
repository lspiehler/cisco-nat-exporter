# prometheus-kuiper-sd

Provides Prometheus a list of targets via HTTP service discovery by querying the Kuiper API. Basic authentication is used to pass the credentials along to the Kuiper API. The hostname for the Kuiper service is passed in the URL as the "target" query parameter. The "application" parameter is passed to get the desired type of servers from the API. For example, valid values include "BCA Web", "Caboodle", "Epic Print Service", "Hyperspace Web", etc. The "groupID" can also be used to filter the returned targets. The value must be the numberical ID of a Kuiper group. It may be used alone or in combination with "application". The "label" parameter is a comma separated list of labels to be returned with each target. Valid labels can be any attribute returned by the API api including "serverType", "maintenanceMode", "associatedApplications", "groups", etc. The maintenance parameter may be supplied to filter which targets are returned based on their current maintanance mode status, for example "in service" or "out of service".

## Run container
```
docker run --name=prometheus-kuiper-sd --restart unless-stopped -d -p 3005:3000 lspiehler/prometheus-kuiper-sd:latest
```

## Configure Prometheus
Example to scrape Kuiper targets
```
- job_name: interfaces
    metrics_path: /probe
    params:
      module: [tls_connect]
    http_sd_configs:
      - url: "http://prometheus-kuiper-sd:3000/kuiper?target=https://kuiper.mydomain.com&application=EpicCareLink&labels=serverType,maintenanceMode&maintanancemode=in%20service"
        basic_auth:
          username: <kuiper_user>
          password: <kuiper_password>
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - source_labels: [hostname]
        target_label: __param_hostname
      - source_labels: [__param_hostname]
        target_label: hostname
      - target_label: __address__
        replacement: blackbox_exporter-cert:9115
```