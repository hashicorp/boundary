# ***
# WARNING: Do not EDIT or MERGE this file, it is generated by packagespec.
# ***

LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_ID             := 00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442
LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_TYPE           := base
LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_BASE_LAYER     := 
LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_SOURCE_INCLUDE := 
LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_SOURCE_EXCLUDE := 
LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_CACHE_KEY_FILE := .buildcache/cache-keys/base-a0554df6c19ccd03a9a1ee035cb15e69108b7442
LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_ARCHIVE_FILE   := .buildcache/archives/00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442.tar.gz
$(eval $(call LAYER,$(LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_ID),$(LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_TYPE),$(LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_BASE_LAYER),$(LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_SOURCE_INCLUDE),$(LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_SOURCE_EXCLUDE),$(LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_CACHE_KEY_FILE),$(LAYER_00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442_ARCHIVE_FILE)))

LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_ID             := 01-ui-990924b65cc3357d39a39ae66c56a32029be4523
LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_TYPE           := ui
LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_BASE_LAYER     := 00-base-a0554df6c19ccd03a9a1ee035cb15e69108b7442
LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_SOURCE_INCLUDE := internal/ui/VERSION
LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_SOURCE_EXCLUDE := 
LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_CACHE_KEY_FILE := .buildcache/cache-keys/ui-990924b65cc3357d39a39ae66c56a32029be4523
LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_ARCHIVE_FILE   := .buildcache/archives/01-ui-990924b65cc3357d39a39ae66c56a32029be4523.tar.gz
$(eval $(call LAYER,$(LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_ID),$(LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_TYPE),$(LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_BASE_LAYER),$(LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_SOURCE_INCLUDE),$(LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_SOURCE_EXCLUDE),$(LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_CACHE_KEY_FILE),$(LAYER_01-ui-990924b65cc3357d39a39ae66c56a32029be4523_ARCHIVE_FILE)))

LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_ID             := 02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128
LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_TYPE           := go-modules
LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_BASE_LAYER     := 01-ui-990924b65cc3357d39a39ae66c56a32029be4523
LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_SOURCE_INCLUDE := go.mod go.sum */go.mod */go.sum
LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_SOURCE_EXCLUDE := 
LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_CACHE_KEY_FILE := .buildcache/cache-keys/go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128
LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_ARCHIVE_FILE   := .buildcache/archives/02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128.tar.gz
$(eval $(call LAYER,$(LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_ID),$(LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_TYPE),$(LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_BASE_LAYER),$(LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_SOURCE_INCLUDE),$(LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_SOURCE_EXCLUDE),$(LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_CACHE_KEY_FILE),$(LAYER_02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128_ARCHIVE_FILE)))

LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_ID             := 03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058
LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_TYPE           := copy-source
LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_BASE_LAYER     := 02-go-modules-36b19bff970f7e940de7cc0a5c11ac1b8281b128
LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_SOURCE_INCLUDE := *.go
LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_SOURCE_EXCLUDE := 
LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_CACHE_KEY_FILE := .buildcache/cache-keys/copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058
LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_ARCHIVE_FILE   := .buildcache/archives/03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058.tar.gz
$(eval $(call LAYER,$(LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_ID),$(LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_TYPE),$(LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_BASE_LAYER),$(LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_SOURCE_INCLUDE),$(LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_SOURCE_EXCLUDE),$(LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_CACHE_KEY_FILE),$(LAYER_03-copy-source-7507a590ca02bfc817431099a5b2a0cb5149f058_ARCHIVE_FILE)))
