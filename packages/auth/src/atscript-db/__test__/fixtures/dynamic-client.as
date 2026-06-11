// Test fixture — mirrors `src/atscript-db/dynamic-client.as`. Compiled by
// `prepareFixtures()` for the integration spec. Keep in sync with the shipped model.
@db.table 'aooth_dynamic_clients'
@db.depth.limit 0
export interface AoothDynamicClient {
    @meta.id
    clientId: string

    clientName?: string

    redirectUris: string
    tokenEndpointAuthMethod: string
    grantTypes: string
    responseTypes: string
    scope?: string

    createdAt: number.timestamp
    lastUsedAt?: number.timestamp
}
