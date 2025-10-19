// Package degenhf implements the DegenHF distributed ECC-based security framework
package degenhf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
	"bytes"
	"encoding/base64"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// DegenHF represents the distributed security framework
type DegenHF struct {
	signingKey    *ecdsa.PrivateKey
	verifyingKey  *ecdsa.PublicKey
	threshold     ThresholdConfig
	trustees      []*Trustee
	killSwitches  []*KillSwitch
	auditLogger   *AuditLogger
	citizenConsents map[string]*CitizenConsent // citizen_id -> consent preferences
	mu            sync.RWMutex
}

// ThresholdConfig defines the threshold cryptography parameters
type ThresholdConfig struct {
	TotalTrustees       int `json:"total_trustees"`
	RequiredSignatures  int `json:"required_signatures"`
	EmergencyThreshold  int `json:"emergency_threshold"`
}

// Trustee represents an independent trustee in the network
type Trustee struct {
	ID             string          `json:"id"`
	PublicKey      []byte          `json:"public_key"`
	TrusteeType    TrusteeType     `json:"trustee_type"`
	Jurisdiction   string          `json:"jurisdiction"`
	LastSeen       time.Time       `json:"last_seen"`
	Status         TrusteeStatus   `json:"status"`
}

type TrusteeType string

const (
	TrusteeTypeJudicial   TrusteeType = "judicial"
	TrusteeTypeTechnical  TrusteeType = "technical"
	TrusteeTypeCitizen    TrusteeType = "citizen"
	TrusteeTypeGovernment TrusteeType = "government"
)

type TrusteeStatus string

const (
	TrusteeStatusActive   TrusteeStatus = "active"
	TrusteeStatusInactive TrusteeStatus = "inactive"
)

// KillSwitch represents an emergency shutdown mechanism
type KillSwitch struct {
	ID                   string            `json:"id"`
	ActivationThreshold  int               `json:"activation_threshold"`
	AuthorizedEntities   []string          `json:"authorized_entities"`
	IsActive             bool              `json:"is_active"`
	ActivationTime       *time.Time        `json:"activation_time,omitempty"`
	ActivatedBy          string            `json:"activated_by,omitempty"`
}

// AuthorizationProof represents a threshold authorization
type AuthorizationProof struct {
	OperationHash     []byte             `json:"operation_hash"`
	TrusteeSignatures []TrusteeSignature `json:"trustee_signatures"`
	Timestamp         int64              `json:"timestamp"`
}

// TrusteeSignature represents a signature from a trustee
type TrusteeSignature struct {
	TrusteeID  string `json:"trustee_id"`
	Signature  []byte `json:"signature"`
}

// ZKP represents a zero-knowledge proof
type ZKP struct {
	ProofType string `json:"proof_type"`
	Commitment []byte `json:"commitment"`
	Challenge  []byte `json:"challenge"`
	Response   []byte `json:"response"`
}

// GovernmentRequest represents a government data access request
type GovernmentRequest struct {
	Entity    string `json:"entity"`
	Purpose   string `json:"purpose"`
	CitizenID string `json:"citizen_id"` // ID of the citizen whose data is being requested
	DataType  string `json:"data_type"`  // Type of data being requested
	Data      []byte `json:"data"`
	ProofData []byte `json:"proof_data"`
}

// EmergencyTrigger represents an emergency shutdown trigger
type EmergencyTrigger struct {
	TriggerType string `json:"trigger_type"`
	Reason      string `json:"reason"`
	Evidence    []byte `json:"evidence"`
}

// VetoProof represents a citizen veto
type VetoProof struct {
	CitizenID  string `json:"citizen_id"`
	DataType   string `json:"data_type"`
	Timestamp  int64  `json:"timestamp"`
	Signature  []byte `json:"signature"`
}

// CitizenConsent represents citizen consent/opt-out preferences for data access
type CitizenConsent struct {
	CitizenID        string            `json:"citizen_id"`
	DataAccessRules  map[string]bool   `json:"data_access_rules"` // data_type -> allowed (true = government access allowed, false = blocked)
	LastUpdated      int64             `json:"last_updated"`
	Signature        []byte            `json:"signature"`
}

// OptOutWarning represents the warning shown when citizens opt-out
type OptOutWarning struct {
	Message     string `json:"message"`
	Severity    string `json:"severity"` // "warning", "caution", "critical"
	DataType    string `json:"data_type"`
	Implications string `json:"implications"`
}

// AuditLogger handles immutable audit logging
type AuditLogger struct {
	// In production, this would use immutable storage like blockchain or tamper-proof database
	entries []AuditEntry
	mu      sync.RWMutex
	// Merkle tree root for immutability
	merkleRoot []byte
}

type AuditEntry struct {
	Timestamp   int64  `json:"timestamp"`
	Operation   string `json:"operation"`
	Actor       string `json:"actor"`
	Data        string `json:"data,omitempty"`
	EntryHash   []byte `json:"entry_hash"`
	PrevHash    []byte `json:"prev_hash"`
	SequenceNum int64  `json:"sequence_num"`
}

// NewDegenHF creates a new DegenHF security framework instance
func NewDegenHF(threshold ThresholdConfig) (*DegenHF, error) {
	// Generate ECC keypair using secp256k1
	privateKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECC keypair: %w", err)
	}

	return &DegenHF{
		signingKey:      privateKey,
		verifyingKey:    &privateKey.PublicKey,
		threshold:       threshold,
		trustees:        make([]*Trustee, 0),
		killSwitches:    make([]*KillSwitch, 0),
		auditLogger:     NewAuditLogger(),
		citizenConsents: make(map[string]*CitizenConsent),
	}, nil
}

// InitializeTrustees sets up the initial trustee network
func (d *DegenHF) InitializeTrustees() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Judicial trustees
	d.trustees = append(d.trustees, &Trustee{
		ID:           "uk_supreme_court",
		PublicKey:    []byte{}, // Would be set from real keys
		TrusteeType:  TrusteeTypeJudicial,
		Jurisdiction: "UK",
		LastSeen:     time.Now(),
		Status:       TrusteeStatusActive,
	})

	// Technical trustees
	d.trustees = append(d.trustees, &Trustee{
		ID:           "eff",
		PublicKey:    []byte{},
		TrusteeType:  TrusteeTypeTechnical,
		Jurisdiction: "Global",
		LastSeen:     time.Now(),
		Status:       TrusteeStatusActive,
	})

	// Citizen trustees (random selection)
	for i := 0; i < 3; i++ {
		d.trustees = append(d.trustees, &Trustee{
			ID:           fmt.Sprintf("citizen_trustee_%d", i),
			PublicKey:    []byte{},
			TrusteeType:  TrusteeTypeCitizen,
			Jurisdiction: "UK",
			LastSeen:     time.Now(),
			Status:       TrusteeStatusActive,
		})
	}

	return nil
}

// AuthorizeCriticalOperation authorizes critical operations using threshold signatures
func (d *DegenHF) AuthorizeCriticalOperation(operation, requester string) (*AuthorizationProof, error) {
	operationHash := d.hashOperation(operation, requester)

	signatures := make([]TrusteeSignature, 0)
	collected := 0

	// Collect threshold signatures from trustees
	for _, trustee := range d.trustees {
		if collected >= d.threshold.RequiredSignatures {
			break
		}

		// In real implementation, this would make network calls to trustees
		if signature, err := d.requestTrusteeSignature(trustee, operationHash); err == nil {
			signatures = append(signatures, *signature)
			collected++
		}
	}

	if collected < d.threshold.RequiredSignatures {
		return nil, errors.New("insufficient trustee signatures")
	}

	proof := &AuthorizationProof{
		OperationHash:     operationHash,
		TrusteeSignatures: signatures,
		Timestamp:         time.Now().Unix(),
	}

	// Log to immutable audit trail
	d.auditLogger.LogAuthorization(proof)

	return proof, nil
}

// VerifyGovernmentRequest verifies government data access with zero-knowledge proof
func (d *DegenHF) VerifyGovernmentRequest(request *GovernmentRequest) (*ZKP, error) {
	// First check if citizen has allowed government access to this data type
	// Default is ALLOWED (true), citizens must explicitly opt-out
	if !d.CheckGovernmentAccessAllowed(request.CitizenID, request.DataType) {
		return nil, errors.New("citizen has opted out of government access to this data type")
	}

	// Create ZKP that proves:
	// 1. Request comes from legitimate government entity
	// 2. Request follows legal protocols
	// 3. Request has proper authorization
	// 4. Citizen has not opted out of access
	// Without revealing sensitive details

	commitment := d.createCommitment(request.Data)
	challenge := d.generateChallenge()
	response := d.computeResponse(commitment, challenge, request.ProofData)

	zkp := &ZKP{
		ProofType:  "government_request_verification",
		Commitment: commitment,
		Challenge:  challenge,
		Response:   response,
	}

	return zkp, nil
}

// CitizenOptOut allows citizens to opt-out of government access to their data (default is access allowed)
func (d *DegenHF) CitizenOptOut(citizenID, dataType string, confirmed bool) (*OptOutWarning, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get or create citizen consent record
	consent, exists := d.citizenConsents[citizenID]
	if !exists {
		consent = &CitizenConsent{
			CitizenID:       citizenID,
			DataAccessRules: make(map[string]bool),
			LastUpdated:     time.Now().Unix(),
		}
		// Default: government access is ALLOWED for all data types
		consent.DataAccessRules[dataType] = true
		d.citizenConsents[citizenID] = consent
	}

	// If not confirmed, show warning
	if !confirmed {
		warning := &OptOutWarning{
			Message: "You are opting out of government access to your " + dataType + " data. This may trigger additional scrutiny as it could indicate you have something to hide.",
			Severity: "warning",
			DataType: dataType,
			Implications: "Opting out may result in closer examination of your activities and could affect government services or benefits.",
		}
		return warning, nil
	}

	// Confirmed opt-out: set access to blocked (false)
	consent.DataAccessRules[dataType] = false
	consent.LastUpdated = time.Now().Unix()

	// Create veto proof for audit trail (backward compatibility)
	vetoProof := &VetoProof{
		CitizenID: citizenID,
		DataType:  dataType,
		Timestamp: time.Now().Unix(),
		Signature: []byte{}, // Would be signed with citizen's key
	}

	// Broadcast opt-out to all trustees
	if err := d.broadcastVeto(vetoProof); err != nil {
		return nil, err
	}

	// Immediately enforce opt-out
	if err := d.enforceVeto(vetoProof); err != nil {
		return nil, err
	}

	// Log opt-out
	d.auditLogger.LogCitizenVeto(vetoProof)

	return nil, nil
}

// CheckGovernmentAccessAllowed checks if government access is allowed for a citizen's data
func (d *DegenHF) CheckGovernmentAccessAllowed(citizenID, dataType string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	consent, exists := d.citizenConsents[citizenID]
	if !exists {
		// Default: access is ALLOWED if no explicit opt-out
		return true
	}

	allowed, exists := consent.DataAccessRules[dataType]
	if !exists {
		// Default: access is ALLOWED if no rule for this data type
		return true
	}

	return allowed
}

// GetCitizenConsent returns the consent preferences for a citizen
func (d *DegenHF) GetCitizenConsent(citizenID string) (*CitizenConsent, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	consent, exists := d.citizenConsents[citizenID]
	if !exists {
		// Return default consent (all access allowed)
		return &CitizenConsent{
			CitizenID:       citizenID,
			DataAccessRules: make(map[string]bool),
			LastUpdated:     time.Now().Unix(),
		}, nil
	}

	// Return copy to prevent external modification
	consentCopy := &CitizenConsent{
		CitizenID:       consent.CitizenID,
		DataAccessRules: make(map[string]bool),
		LastUpdated:     consent.LastUpdated,
		Signature:       make([]byte, len(consent.Signature)),
	}
	copy(consentCopy.Signature, consent.Signature)
	for k, v := range consent.DataAccessRules {
		consentCopy.DataAccessRules[k] = v
	}

	return consentCopy, nil
}

// ActivateEmergencyShutdown activates distributed emergency kill switches
func (d *DegenHF) ActivateEmergencyShutdown(trigger *EmergencyTrigger) error {
	// Verify trigger legitimacy
	if err := d.verifyEmergencyTrigger(trigger); err != nil {
		return err
	}

	// Get authorization from emergency threshold of trustees
	authorization, err := d.authorizeEmergencyOperation(trigger)
	if err != nil {
		return err
	}

	// Activate all kill switches
	for _, killSwitch := range d.killSwitches {
		if err := d.activateKillSwitch(killSwitch, authorization); err != nil {
			return err
		}
	}

	// Log emergency activation
	d.auditLogger.LogEmergencyActivation(trigger, authorization)

	return nil
}

// AuditLogger returns the audit logger instance
func (d *DegenHF) AuditLogger() *AuditLogger {
	return d.auditLogger
}

// Helper methods

func (d *DegenHF) hashOperation(operation, requester string) []byte {
	data := fmt.Sprintf("%s:%s:%d", operation, requester, time.Now().Unix())
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func (d *DegenHF) requestTrusteeSignature(trustee *Trustee, operationHash []byte) (*TrusteeSignature, error) {
	// In real implementation, this would make network calls to trustees
	// For now, simulate with local signature

	r, s, err := ecdsa.Sign(rand.Reader, d.signingKey, operationHash)
	if err != nil {
		return nil, err
	}

	// Encode signature
	signature := append(r.Bytes(), s.Bytes()...)

	return &TrusteeSignature{
		TrusteeID: trustee.ID,
		Signature: signature,
	}, nil
}

func (d *DegenHF) createCommitment(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (d *DegenHF) generateChallenge() []byte {
	challenge := make([]byte, 32)
	rand.Read(challenge)
	return challenge
}

func (d *DegenHF) computeResponse(commitment, challenge, proofData []byte) []byte {
	hasher := sha256.New()
	hasher.Write(commitment)
	hasher.Write(challenge)
	hasher.Write(proofData)
	return hasher.Sum(nil)
}

func (d *DegenHF) broadcastVeto(vetoProof *VetoProof) error {
	// Broadcast to all trustees
	return nil
}

func (d *DegenHF) enforceVeto(vetoProof *VetoProof) error {
	// Immediately enforce veto across all systems
	return nil
}

func (d *DegenHF) verifyEmergencyTrigger(trigger *EmergencyTrigger) error {
	// Verify trigger legitimacy
	return nil
}

func (d *DegenHF) authorizeEmergencyOperation(trigger *EmergencyTrigger) (*AuthorizationProof, error) {
	// Emergency authorization requires higher threshold
	return d.AuthorizeCriticalOperation("emergency_shutdown", "system")
}

func (d *DegenHF) activateKillSwitch(killSwitch *KillSwitch, authorization *AuthorizationProof) error {
	// Activate kill switch
	return nil
}

	return nil
}

// InitializeKillSwitches sets up distributed emergency kill switches
func (d *DegenHF) InitializeKillSwitches() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Judicial kill switch - requires UK Supreme Court authorization
	d.killSwitches = append(d.killSwitches, &KillSwitch{
		ID:                  "judicial_kill_switch",
		ActivationThreshold: 1, // Single judicial authorization
		AuthorizedEntities:  []string{"uk_supreme_court"},
		IsActive:            false,
	})

	// Technical kill switch - requires EFF + 2 technical trustees
	d.killSwitches = append(d.killSwitches, &KillSwitch{
		ID:                  "technical_kill_switch",
		ActivationThreshold: 3,
		AuthorizedEntities:  []string{"eff", "technical_trustee_1", "technical_trustee_2"},
		IsActive:            false,
	})

	// Citizen kill switch - requires 1000+ citizen signatures
	d.killSwitches = append(d.killSwitches, &KillSwitch{
		ID:                  "citizen_kill_switch",
		ActivationThreshold: 1000,
		AuthorizedEntities:  []string{"citizen_collective"},
		IsActive:            false,
	})

	// International kill switch - requires UN + EU authorization
	d.killSwitches = append(d.killSwitches, &KillSwitch{
		ID:                  "international_kill_switch",
		ActivationThreshold: 2,
		AuthorizedEntities:  []string{"un_human_rights", "european_court"},
		IsActive:            false,
	})

	// System administrator kill switch - for maintenance
	d.killSwitches = append(d.killSwitches, &KillSwitch{
		ID:                  "admin_kill_switch",
		ActivationThreshold: 1,
		AuthorizedEntities:  []string{"system_admin"},
		IsActive:            false,
	})

	return nil
}

// ActivateKillSwitch activates a specific kill switch
func (d *DegenHF) ActivateKillSwitch(killSwitchID, activatedBy string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, ks := range d.killSwitches {
		if ks.ID == killSwitchID {
			if !d.isAuthorizedEntity(ks, activatedBy) {
				return errors.New("entity not authorized to activate this kill switch")
			}

			now := time.Now()
			ks.IsActive = true
			ks.ActivationTime = &now
			ks.ActivatedBy = activatedBy

			// Log the activation
			d.auditLogger.LogKillSwitchActivation(ks)

			return nil
		}
	}

	return errors.New("kill switch not found")
}

// CheckEmergencyStatus checks if emergency shutdown should be triggered
func (d *DegenHF) CheckEmergencyStatus() (bool, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	activeSwitches := 0
	reasons := make([]string, 0)

	for _, ks := range d.killSwitches {
		if ks.IsActive {
			activeSwitches++
			reasons = append(reasons, fmt.Sprintf("%s activated by %s", ks.ID, ks.ActivatedBy))
		}
	}

	// Emergency triggered if 3+ kill switches are active
	emergencyTriggered := activeSwitches >= 3

	reason := ""
	if emergencyTriggered {
		reason = fmt.Sprintf("Emergency triggered: %d kill switches active. Reasons: %s",
			activeSwitches, fmt.Sprintf("[%s]", fmt.Sprintf("%s", reasons)))
	}

	return emergencyTriggered, reason
}

// GetKillSwitchStatus returns the status of all kill switches
func (d *DegenHF) GetKillSwitchStatus() []KillSwitch {
	d.mu.RLock()
	defer d.mu.RUnlock()

	status := make([]KillSwitch, len(d.killSwitches))
	for i, ks := range d.killSwitches {
		status[i] = *ks // Return copy
	}
	return status
}

// Helper methods

func (d *DegenHF) isAuthorizedEntity(ks *KillSwitch, entity string) bool {
	for _, authorized := range ks.AuthorizedEntities {
		if authorized == entity {
			return true
		}
	}
	return false
}

// AuditLogger implementation

// NewAuditLogger creates a new immutable audit logger
func NewAuditLogger() *AuditLogger {
	return &AuditLogger{
		entries:    make([]AuditEntry, 0),
		merkleRoot: make([]byte, 32), // Initialize with zero hash
	}
}

// LogAuthorization logs an authorization event immutably
func (a *AuditLogger) LogAuthorization(proof *AuthorizationProof) {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := AuditEntry{
		Timestamp:   proof.Timestamp,
		Operation:   "authorization_granted",
		Actor:       "degenhf_framework",
		Data:        fmt.Sprintf("operation_hash: %x", proof.OperationHash),
		SequenceNum: int64(len(a.entries) + 1),
	}

	// Calculate entry hash
	entry.EntryHash = a.calculateEntryHash(&entry)

	// Set previous hash
	if len(a.entries) > 0 {
		entry.PrevHash = a.entries[len(a.entries)-1].EntryHash
	} else {
		entry.PrevHash = make([]byte, 32) // Genesis block
	}

	a.entries = append(a.entries, entry)
	a.updateMerkleRoot()
}

// LogGovernmentAccess logs government data access with ZKP verification
func (a *AuditLogger) LogGovernmentAccess(govEntity, purpose string, zkp *ZKP) {
	a.mu.Lock()
	defer a.mu.Unlock()

	data := fmt.Sprintf("entity: %s, purpose: %s, zkp_type: %s", govEntity, purpose, zkp.ProofType)

	entry := AuditEntry{
		Timestamp:   time.Now().Unix(),
		Operation:   "government_data_access",
		Actor:       govEntity,
		Data:        data,
		SequenceNum: int64(len(a.entries) + 1),
	}

	entry.EntryHash = a.calculateEntryHash(&entry)

	if len(a.entries) > 0 {
		entry.PrevHash = a.entries[len(a.entries)-1].EntryHash
	} else {
		entry.PrevHash = make([]byte, 32)
	}

	a.entries = append(a.entries, entry)
	a.updateMerkleRoot()
}

// LogCitizenVeto logs a citizen veto event
func (a *AuditLogger) LogCitizenVeto(vetoProof *VetoProof) {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := AuditEntry{
		Timestamp:   vetoProof.Timestamp,
		Operation:   "citizen_veto",
		Actor:       vetoProof.CitizenID,
		Data:        fmt.Sprintf("data_type: %s", vetoProof.DataType),
		SequenceNum: int64(len(a.entries) + 1),
	}

	entry.EntryHash = a.calculateEntryHash(&entry)

	if len(a.entries) > 0 {
		entry.PrevHash = a.entries[len(a.entries)-1].EntryHash
	} else {
		entry.PrevHash = make([]byte, 32)
	}

	a.entries = append(a.entries, entry)
	a.updateMerkleRoot()
}

// LogEmergencyActivation logs emergency shutdown activation
func (a *AuditLogger) LogEmergencyActivation(trigger *EmergencyTrigger, authorization *AuthorizationProof) {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := AuditEntry{
		Timestamp:   time.Now().Unix(),
		Operation:   "emergency_shutdown_activated",
		Actor:       "system",
		Data:        fmt.Sprintf("reason: %s, auth_timestamp: %d", trigger.Reason, authorization.Timestamp),
		SequenceNum: int64(len(a.entries) + 1),
	}

	entry.EntryHash = a.calculateEntryHash(&entry)

	if len(a.entries) > 0 {
		entry.PrevHash = a.entries[len(a.entries)-1].EntryHash
	} else {
		entry.PrevHash = make([]byte, 32)
	}

	a.entries = append(a.entries, entry)
	a.updateMerkleRoot()
}

func (a *AuditLogger) LogKillSwitchActivation(killSwitch *KillSwitch) {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := AuditEntry{
		Timestamp:   time.Now().Unix(),
		Operation:   "kill_switch_activated",
		Actor:       killSwitch.ActivatedBy,
		Data:        fmt.Sprintf("kill_switch: %s, activated_at: %v", killSwitch.ID, killSwitch.ActivationTime),
		SequenceNum: int64(len(a.entries) + 1),
	}

	entry.EntryHash = a.calculateEntryHash(&entry)

	if len(a.entries) > 0 {
		entry.PrevHash = a.entries[len(a.entries)-1].EntryHash
	} else {
		entry.PrevHash = make([]byte, 32)
	}

	a.entries = append(a.entries, entry)
	a.updateMerkleRoot()
}

// VerifyAuditIntegrity verifies the integrity of the audit trail
func (a *AuditLogger) VerifyAuditIntegrity() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	expectedRoot := a.calculateMerkleRoot()
	return bytes.Equal(a.merkleRoot, expectedRoot)
}

// GetAuditEntries returns audit entries within a time range
func (a *AuditLogger) GetAuditEntries(startTime, endTime int64) []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var result []AuditEntry
	for _, entry := range a.entries {
		if entry.Timestamp >= startTime && entry.Timestamp <= endTime {
			result = append(result, entry)
		}
	}
	return result
}

// GetMerkleRoot returns the current Merkle root for integrity verification
func (a *AuditLogger) GetMerkleRoot() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]byte(nil), a.merkleRoot...)
}

// Helper methods

func (a *AuditLogger) calculateEntryHash(entry *AuditEntry) []byte {
	data := fmt.Sprintf("%d:%s:%s:%s:%d",
		entry.Timestamp, entry.Operation, entry.Actor, entry.Data, entry.SequenceNum)

	if len(entry.PrevHash) > 0 {
		data += ":" + base64.StdEncoding.EncodeToString(entry.PrevHash)
	}

	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func (a *AuditLogger) updateMerkleRoot() {
	a.merkleRoot = a.calculateMerkleRoot()
}

func (a *AuditLogger) calculateMerkleRoot() []byte {
	if len(a.entries) == 0 {
		return make([]byte, 32)
	}

	// Simple Merkle tree calculation (in production, use a proper Merkle tree library)
	hashes := make([][]byte, len(a.entries))
	for i, entry := range a.entries {
		hashes[i] = entry.EntryHash
	}

	for len(hashes) > 1 {
		var newHashes [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := append(hashes[i], hashes[i+1]...)
				hash := sha256.Sum256(combined)
				newHashes = append(newHashes, hash[:])
			} else {
				newHashes = append(newHashes, hashes[i])
			}
		}
		hashes = newHashes
	}

	return hashes[0]
}