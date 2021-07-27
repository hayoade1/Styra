
data.global.istio.mesh

monitor[decision] {
  data.library.v1.kubernetes.admission.workload.v1.expect_container_resource_requests[message]

  decision := {
    "allowed": true,
    "message": message
  }
}

monitor[decision] {
  data.library.v1.kubernetes.admission.workload.v1.block_privileged_mode[message]

  decision := {
    "allowed": false,
    "message": message
  }
}



monitor[decision] {
  data.library.v1.kubernetes.admission.network.v1.ingress_missing_tls[message]

  decision := {
    "allowed": false,
    "message": message
  }
}

monitor[decision] {
  data.library.v1.kubernetes.admission.network.v1.ingress_hostpath_conflict[message]

  decision := {
    "allowed": false,
    "message": message
  }
}
