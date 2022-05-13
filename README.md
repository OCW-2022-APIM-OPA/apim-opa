# APIM ❤️ OPA OCW Hack

The project aims to demo an integration between Azure APIM and Open Policy Agent for authorizing REST API calls.

## Architecture overview

![image](https://user-images.githubusercontent.com/6428634/168282443-07b7298e-1e00-4044-859e-6438963a934a.png)

Request information, including the domain, path and some headers (in particular Authorization) are sent to OPA by APIM. OPA will determine if the request is allowed or not, and APIM will enforce this decision by forwarding the request or sending an Unauthorized response.

## Project status

The project is work in progress. The backlog can be found [here](https://github.com/orgs/OCW-2022-APIM-OPA/projects/1)
