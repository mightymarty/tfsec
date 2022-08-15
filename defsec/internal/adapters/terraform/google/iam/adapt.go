package iam

import (
	"github.com/google/uuid"
	"github.com/mightymarty/tfsec/defsec/internal/types"
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/iam"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) iam2.IAM {
	return (&adapter{
		orgs:    make(map[string]iam2.Organization),
		modules: modules,
	}).Adapt()
}

type adapter struct {
	modules terraform2.Modules
	orgs    map[string]iam2.Organization
	folders []parentedFolder
	projects []parentedProject
}

func (a *adapter) Adapt() iam2.IAM {
	a.adaptOrganizationIAM()
	a.adaptFolders()
	a.adaptFolderIAM()
	a.adaptProjects()
	a.adaptProjectIAM()
	return a.merge()
}

func (a *adapter) addOrg(blockID string) {
	if _, ok := a.orgs[blockID]; !ok {
		a.orgs[blockID] = iam2.Organization{
			Metadata: types.NewUnmanagedMetadata(),
		}
	}
}

func (a *adapter) merge() iam2.IAM {

	// add projects to folders, orgs
PROJECT:
	for _, project := range a.projects {
		for i, folder := range a.folders {
			if project.folderBlockID != "" && project.folderBlockID == folder.blockID {
				folder.folder.Projects = append(folder.folder.Projects, project.project)
				a.folders[i] = folder
				continue PROJECT
			}
		}
		if project.orgBlockID != "" {
			if org, ok := a.orgs[project.orgBlockID]; ok {
				org.Projects = append(org.Projects, project.project)
				a.orgs[project.orgBlockID] = org
				continue PROJECT
			}
		}

		var org iam2.Organization
		org.Metadata = types.NewUnmanagedMetadata()
		org.Projects = append(org.Projects, project.project)
		a.orgs[uuid.NewString()] = org
	}

	// add folders to folders, orgs
FOLDER_NESTED:
	for _, folder := range a.folders {
		for i, existing := range a.folders {
			if folder.parentBlockID != "" && folder.parentBlockID == existing.blockID {
				existing.folder.Folders = append(existing.folder.Folders, folder.folder)
				a.folders[i] = existing
				continue FOLDER_NESTED
			}

		}
	}
FOLDER_ORG:
	for _, folder := range a.folders {
		if folder.parentBlockID != "" {
			if org, ok := a.orgs[folder.parentBlockID]; ok {
				org.Folders = append(org.Folders, folder.folder)
				a.orgs[folder.parentBlockID] = org
				continue FOLDER_ORG
			}
		} else {
			// add to placeholder?
			var org iam2.Organization
			org.Metadata = types.NewUnmanagedMetadata()
			org.Folders = append(org.Folders, folder.folder)
			a.orgs[uuid.NewString()] = org
		}
	}

	var output iam2.IAM
	for _, org := range a.orgs {
		output.Organizations = append(output.Organizations, org)
	}
	return output
}
